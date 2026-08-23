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
import { readFileSync } from 'fs';
import * as path from 'path';

/**
 * Read the release from the VERSION file rather than a hardcoded literal.
 *
 * The literal fallback meant every stack deployed since 1.1.0 advertised
 * "version: 1.0.0" in its CloudFormation description unless the VERSION
 * environment variable happened to be exported by the build, which is the
 * value operators use to identify what they are running.
 */
const versionFromFile = (): string => {
    try {
        return readFileSync(path.join(__dirname, '..', '..', 'VERSION'), 'utf-8').trim();
    } catch {
        return '0.0.0';
    }
};

export const SOLUTION_VERSION = process.env['VERSION'] || versionFromFile();

export const SOLUTION_NAME = process.env['SOLUTION_NAME']
    ? process.env['SOLUTION_NAME']
    : 'AWS-EC2-Forensics-Orchestrator';

export const SOLUTION_ID = process.env['SOLUTION_ID']
    ? process.env['SOLUTION_ID']
    : 'SO0191';

export const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET']
    ? process.env['DIST_OUTPUT_BUCKET']
    : '';

export const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME']
    ? process.env['SOLUTION_TRADEMARKEDNAME']
    : 'AWS-EC2-Forensics-Orchestrator';

export const SOLUTION_PROVIDER = 'AWS Solution Development';

export const ENV_NAME = process.env['ENV_NAME'] || 'dev';
