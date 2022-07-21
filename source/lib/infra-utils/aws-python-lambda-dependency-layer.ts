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
import { Code, LayerVersion, Runtime } from 'aws-cdk-lib/aws-lambda';
import * as child_process from 'child_process';
import { Construct } from 'constructs';
import * as path from 'path';

export const DEFAULT_PYTHON_VERSION = Runtime.PYTHON_3_9;

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
    public readonly layer: LayerVersion;

    constructor(scope: Construct) {
        super(scope, ID);
        const requirementsFile = this.getDependencySpec();
        const outputDir = `../.build/lambda-common`;
        const pipeInstallCmd = `pip install -r ${requirementsFile} -t ${outputDir}/python`;
        try {
            child_process.execSync(pipeInstallCmd);
        } catch (error) {
            Annotations.of(this).addError('Error installing python dependencies abort');
        }

        const layerID = `python-lambda-common-layer`;
        const code = Code.fromAsset(outputDir);

        this.layer = new LayerVersion(this, layerID, {
            code: code,
            compatibleRuntimes: [DEFAULT_PYTHON_VERSION],
            license: 'Apache-2.0',
            layerVersionName: layerID,
            description: 'A layer to load the python common dependencies',
        });
    }

    createDependencyLayer(projectName: string, functionName: string): LayerVersion {
        const requirementsFile = this.getDependencySpec();
        const outputDir = `../.build/${functionName}`;
        const pipeInstallCmd = `pip install -r ${requirementsFile} -t ${outputDir}/python`;
        try {
            child_process.execSync(pipeInstallCmd);
        } catch (error) {
            Annotations.of(this).addError('Error installing python dependencies abort');
        }

        const layerID = `${projectName}-${functionName}-dependencies`;
        const code = Code.fromAsset(outputDir);

        return new LayerVersion(this, layerID, {
            code: code,
            compatibleRuntimes: [DEFAULT_PYTHON_VERSION],
            license: 'Apache-2.0',
            layerVersionName: `${functionName}-layer`,
            description: 'A layer to load the python dependencies',
        });
    }

    private getDependencySpec() {
        return path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH, `requirements.txt`);
    }
}
