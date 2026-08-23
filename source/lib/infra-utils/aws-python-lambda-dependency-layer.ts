/* 
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

import { Annotations, Stack } from 'aws-cdk-lib';
import { Architecture, Code, LayerVersion, Runtime } from 'aws-cdk-lib/aws-lambda';
import * as child_process from 'child_process';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export const DEFAULT_PYTHON_VERSION = Runtime.PYTHON_3_12;

/**
 * Architecture the layer's wheels are built for. The Lambda functions in this
 * solution do not set `architecture`, so they take the CDK/CloudFormation
 * default of x86_64. The layer must be built for the same architecture, so if
 * the functions ever move to arm64 this constant has to move with them.
 */
export const DEFAULT_LAMBDA_ARCHITECTURE = Architecture.X86_64;

/**
 * pip `--platform` tag for each supported Lambda architecture. Lambda's
 * python3.12 runtime is AL2023 based (glibc 2.34), so the manylinux2014
 * (glibc 2.17) baseline is satisfied.
 */
const PIP_PLATFORM_BY_ARCHITECTURE: Record<string, string> = {
    [Architecture.X86_64.name]: 'manylinux2014_x86_64',
    [Architecture.ARM_64.name]: 'manylinux2014_aarch64',
};

/**
 * Lambda's hard quota for the unzipped size of a function and all of its
 * layers. Breaching it fails the LayerVersion publish with
 * "Unzipped size must be smaller than 262144000 bytes".
 */
const LAMBDA_UNZIPPED_SIZE_LIMIT_BYTES = 262144000;

/** Warn once the layer passes this share of the quota. */
const LAMBDA_UNZIPPED_SIZE_WARN_PERCENT = 90;

const cachedCommonLayer = new Map<string, LayerVersion>();
const ID = 'DEFAULT_ID_PYTHON_COMMON_LAYER';

export function getPythonCommonDependencyLayer(scope: Construct) {
    const stackIdentifier = Stack.of(scope).stackName;
    if (!cachedCommonLayer.get(stackIdentifier)) {
        cachedCommonLayer.set(stackIdentifier, new PythonLambdaLayerVersion(scope).layer);
    }
    return cachedCommonLayer.get(stackIdentifier)!;
}

/**
 * Python lambda common dependency layer construct
 */
class PythonLambdaLayerVersion extends Construct {
    private readonly LAMBDA_RELATIVE_PATH = '../../lambda';
    /**
     * Where the layer is staged, relative to this file. Anchored on `__dirname` rather
     * than on the process cwd: this directory is deleted recursively before every build,
     * and resolving it against the cwd meant `cdk synth` from anywhere other than
     * `source/` deleted `<cwd>/../.build/lambda-common`.
     */
    private readonly BUILD_RELATIVE_PATH = '../../../.build';
    public readonly layer: LayerVersion;

    constructor(scope: Construct) {
        super(scope, ID);
        const outputDir = this.buildDir('lambda-common');
        this.installDependencies(outputDir);

        const layerID = `python-lambda-common-layer`;
        const code = Code.fromAsset(outputDir);

        this.layer = new LayerVersion(this, layerID, {
            code: code,
            compatibleRuntimes: [DEFAULT_PYTHON_VERSION],
            compatibleArchitectures: [DEFAULT_LAMBDA_ARCHITECTURE],
            license: 'Apache-2.0',
            layerVersionName: layerID,
            description: 'A layer to load the python common dependencies',
        });
    }

    createDependencyLayer(projectName: string, functionName: string): LayerVersion {
        const outputDir = this.buildDir(functionName);
        this.installDependencies(outputDir);

        const layerID = `${projectName}-${functionName}-dependencies`;
        const code = Code.fromAsset(outputDir);

        return new LayerVersion(this, layerID, {
            code: code,
            compatibleRuntimes: [DEFAULT_PYTHON_VERSION],
            compatibleArchitectures: [DEFAULT_LAMBDA_ARCHITECTURE],
            license: 'Apache-2.0',
            layerVersionName: `${functionName}-layer`,
            description: 'A layer to load the python dependencies',
        });
    }

    /**
     * Install the layer's python dependencies into `outputDir`, targeting the
     * Lambda execution environment rather than the machine running `cdk synth`.
     *
     * Without the platform/version/abi flags, pip resolves wheels for the build
     * host, so a developer synthesizing on macOS or an arm64 workstation
     * silently ships incompatible binaries (for example
     * `aiohttp/_http_parser.cpython-312-darwin.so`) inside a Linux x86_64
     * layer. That failure only surfaces at Lambda invocation time.
     *
     * `--only-binary=:all:` is what makes this safe: if a dependency has no
     * matching manylinux wheel, pip fails loudly instead of building it from
     * source against the wrong interpreter and platform.
     */
    private installDependencies(outputDir: string) {
        // pip leaves pre-existing content in a `-t` target in place, so a stale
        // build from another host (or another python version) would be baked
        // into the asset. Start from a clean directory to keep the layer
        // contents deterministic.
        fs.rmSync(outputDir, { recursive: true, force: true });

        const pipInstallCmd = [
            'pip install',
            `-r ${this.getDependencySpec()}`,
            `-t ${outputDir}/python`,
            `--platform ${this.getPipPlatform()}`,
            `--python-version ${this.getPipPythonVersion()}`,
            '--implementation cp',
            '--only-binary=:all:',
            // pip writes timestamp based (PEP 552 "unchecked hash" predecessor)
            // .pyc files, whose header carries the source mtime. Because the
            // directory above is rebuilt from scratch on every synth, those
            // mtimes move, and two synths of identical dependencies produced
            // two different asset hashes and so a pointless new LayerVersion
            // and function update on every deploy. Bytecode is still wanted -
            // /opt is read only at run time so CPython cannot cache it there,
            // and dropping it cost measurable cold start - so it is generated
            // below with hash based invalidation instead.
            '--no-compile',
        ].join(' ');

        try {
            child_process.execSync(pipInstallCmd, { stdio: 'pipe' });
        } catch (error) {
            // Surface pip's own output. With --only-binary=:all: the usual
            // cause is a dependency with no wheel for this platform, and the
            // package name only appears in pip's stderr.
            const details =
                error instanceof Error && 'stderr' in error
                    ? `${(error as { stderr?: Buffer }).stderr ?? ''}`.trim()
                    : `${error}`;
            Annotations.of(this).addError(
                `Error installing python dependencies abort. Command: ${pipInstallCmd}. ${details}`
            );
        }

        this.compileBytecode(outputDir);
        this.assertWithinUnzippedSizeLimit(outputDir);
    }

    /**
     * Byte-compile the installed dependencies with hash based invalidation.
     *
     * `--invalidation-mode checked-hash` (PEP 552) writes the hash of the source
     * into the .pyc instead of its mtime and size, so the same sources always
     * produce byte identical .pyc files and the layer asset hash is stable
     * across synths. Lambda mounts a layer read only at `/opt`, so without
     * bytecode in the asset CPython recompiles every module on every cold
     * start and cannot cache the result.
     *
     * The compiling interpreter has to be the runtime's minor version or the
     * magic number in the .pyc will not match and Lambda ignores the file.
     */
    private compileBytecode(outputDir: string) {
        const pythonDir = path.join(outputDir, 'python');
        if (!fs.existsSync(pythonDir)) {
            return;
        }

        const interpreter = this.resolveRuntimeInterpreter();
        if (!interpreter) {
            Annotations.of(this).addWarning(
                `No python ${this.getPipPythonVersion()} interpreter was found on PATH, so the ` +
                    `layer ships without byte-compiled dependencies. Every cold start will ` +
                    `recompile them, because a layer is mounted read only at /opt.`
            );
            return;
        }

        const compileCmd = `${interpreter} -m compileall -q --invalidation-mode checked-hash ${pythonDir}`;

        try {
            child_process.execSync(compileCmd, { stdio: 'pipe' });
        } catch (error) {
            // A dependency that ships a py2-only or deliberately invalid module
            // fails compileall for that file only. The layer is still complete
            // and still deterministic, so warn rather than fail the synth.
            const details =
                error instanceof Error && 'stdout' in error
                    ? `${(error as { stdout?: Buffer }).stdout ?? ''}`.trim()
                    : `${error}`;
            Annotations.of(this).addWarning(
                `Not every dependency byte-compiled. Command: ${compileCmd}. ${details}`
            );
        }
    }

    /**
     * First interpreter on PATH whose minor version matches the Lambda runtime,
     * or undefined when there is none.
     */
    private resolveRuntimeInterpreter(): string | undefined {
        const version = this.getPipPythonVersion();

        for (const candidate of [`python${version}`, 'python3']) {
            try {
                const reported = child_process
                    .execSync(`${candidate} --version`, { stdio: 'pipe' })
                    .toString();
                if (reported.startsWith(`Python ${version}.`)) {
                    return candidate;
                }
            } catch {
                // Not on PATH. Try the next candidate.
            }
        }

        return undefined;
    }

    /**
     * Absolute staging directory for a layer, anchored on this file's location so
     * that it does not depend on the directory `cdk synth` runs in.
     */
    private buildDir(name: string): string {
        return path.resolve(__dirname, this.BUILD_RELATIVE_PATH, name);
    }

    /**
     * Fail `cdk synth` if the built layer breaches Lambda's unzipped size
     * quota, and warn while it is merely close to it.
     *
     * Lambda rejects an oversized layer at publish time, so without this check
     * the only signal is a CloudFormation failure and stack rollback partway
     * through a deploy. Checking at synth moves that feedback into the build.
     *
     * The quota applies to the function plus all of its layers, so the layer
     * itself has to stay meaningfully under the limit rather than merely fit.
     */
    private assertWithinUnzippedSizeLimit(outputDir: string) {
        if (!fs.existsSync(outputDir)) {
            return;
        }

        const totalBytes = this.getDirectorySizeInBytes(outputDir);
        const percentOfLimit = (totalBytes / LAMBDA_UNZIPPED_SIZE_LIMIT_BYTES) * 100;
        const summary =
            `${outputDir} unzipped size is ${totalBytes} bytes ` +
            `(${percentOfLimit.toFixed(
                1
            )}% of the ${LAMBDA_UNZIPPED_SIZE_LIMIT_BYTES} byte Lambda limit)`;

        if (totalBytes >= LAMBDA_UNZIPPED_SIZE_LIMIT_BYTES) {
            Annotations.of(this).addError(
                `${summary}. Lambda will reject this layer at publish time. ` +
                    `Remove dependencies from lambda/requirements.in that lambda/src does not import, ` +
                    `or split the layer per function via createDependencyLayer.`
            );
        } else if (percentOfLimit >= LAMBDA_UNZIPPED_SIZE_WARN_PERCENT) {
            Annotations.of(this).addWarning(
                `${summary}. This leaves little room for dependency growth.`
            );
        }
    }

    private getDirectorySizeInBytes(dir: string): number {
        let total = 0;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                total += this.getDirectorySizeInBytes(full);
            } else if (entry.isFile()) {
                total += fs.statSync(full).size;
            }
        }
        return total;
    }

    private getPipPlatform() {
        const platform = PIP_PLATFORM_BY_ARCHITECTURE[DEFAULT_LAMBDA_ARCHITECTURE.name];
        if (!platform) {
            Annotations.of(this).addError(
                `No pip platform tag mapped for Lambda architecture ${DEFAULT_LAMBDA_ARCHITECTURE.name}`
            );
        }
        return platform;
    }

    private getPipPythonVersion() {
        // Runtime.name is e.g. 'python3.12'; pip wants '3.12'.
        return DEFAULT_PYTHON_VERSION.name.replace('python', '');
    }

    private getDependencySpec() {
        return path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH, `requirements.txt`);
    }
}
