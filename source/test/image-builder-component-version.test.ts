/*********************************************************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                *
 *                                                                                                                    *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    *
 *  with the License. A copy of the License is located at                                                             *
 *                                                                                                                    *
 *      http://www.apache.org/licenses/LICENSE-2.0                                                                    *
 *                                                                                                                    *
 *  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES  *
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    *
 *  and limitations under the License.                                                                                *
 *********************************************************************************************************************/

/**
 * EC2 Image Builder component and recipe versions are immutable.
 *
 * CreateComponent fails with "component with the same name and version already
 * exists" if the version is unchanged but Data differs, and CreateImageRecipe
 * behaves the same way. So editing a file under image-builder-components/
 * without bumping `version` in the cdk.json `imageBuilderPipelines` entry makes
 * `cdk deploy ForensicImageBuilderStack` fail - at deploy time, in whatever
 * account is being deployed to, with no local signal beforehand.
 *
 * That has already happened twice in this repo's history (1.0.0 -> 1.1.0, and
 * again when this guard was added). This test turns it into a local failure with
 * an actionable message.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const COMPONENT_DIR = path.join(__dirname, '..', 'image-builder-components');
const LOCK_FILE = path.join(COMPONENT_DIR, 'component-versions.json');
const CDK_JSON = path.join(__dirname, '..', 'cdk.json');

interface Lock {
    version: string;
    components: Record<string, string>;
}

interface PipelineEntry {
    name: string;
    dir: string;
    version: string;
}

function sha256(file: string): string {
    return crypto
        .createHash('sha256')
        .update(fs.readFileSync(file))
        .digest('hex');
}

const lock: Lock = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf-8'));
const cdkJson = JSON.parse(fs.readFileSync(CDK_JSON, 'utf-8'));
const pipelines: PipelineEntry[] =
    cdkJson.context.imageBuilderPipelines ?? [];
const componentFiles = fs
    .readdirSync(COMPONENT_DIR)
    .filter((name) => name.endsWith('.yml'))
    .sort();

describe('image builder component versioning', () => {
    it('has at least one component and one pipeline, so this is not vacuous', () => {
        expect(componentFiles.length).toBeGreaterThan(0);
        expect(pipelines.length).toBeGreaterThan(0);
    });

    it('records a hash for every component file', () => {
        expect(Object.keys(lock.components).sort()).toEqual(componentFiles);
    });

    it.each(componentFiles)(
        '%s is unchanged since the recorded version, or the version was bumped',
        (name) => {
            const actual = sha256(path.join(COMPONENT_DIR, name));
            const recorded = lock.components[name];
            if (recorded !== actual) {
                throw new Error(
                    `${name} has changed but image builder component versions ` +
                        `are immutable, so CreateComponent will fail at deploy ` +
                        `time with the version already recorded here ` +
                        `(${lock.version}).\n` +
                        `Bump "version" in the cdk.json imageBuilderPipelines ` +
                        `entry, set "version" in ` +
                        `image-builder-components/component-versions.json to ` +
                        `match, and update the hash for ${name} to ${actual}.`
                );
            }
        }
    );

    it('the pipeline version in cdk.json matches the recorded version', () => {
        for (const pipeline of pipelines) {
            expect(pipeline.version).toEqual(lock.version);
        }
    });

    it('the recorded version is a three part semantic version', () => {
        // Image Builder requires major.minor.patch with numeric parts.
        expect(lock.version).toMatch(/^\d+\.\d+\.\d+$/);
    });
});
