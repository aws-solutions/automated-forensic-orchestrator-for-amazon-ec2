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
export const SOLUTION_VERSION = process.env['VERSION'] || '1.0.0';

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
