/**
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 *  with the License. A copy of the License is located at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

import { readFileSync, readdirSync } from 'fs';
import * as path from 'path';
import {
    SSM_DIRECTORY,
    HYPHEN,
    SSM_EXECUTION_TIMEOUT_CONTEXT_VALUE,
    SSM_EXECUTION_TIMEOUT_ENV_VAR,
} from './infra-utils/infra-types';
import { Construct } from 'constructs';
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AwsForensicsSSMDBuilderConstructProps {}

/**
 * Forensics solutions SSM Document builder constructs stack
 */
export class ForensicSSMDBuilderConstruct extends Construct {
    public lambdaEnvironmentProps: {
        [key: string]: string;
    };
    constructor(
        scope: Construct,
        id: string,
        props: AwsForensicsSSMDBuilderConstructProps
    ) {
        super(scope, id);

        //Get SSM Document directory details from json
        const SSMDocumentsDir = this.node.tryGetContext(SSM_DIRECTORY);
        const ssmExecutionTimeout = this.node.tryGetContext(
            SSM_EXECUTION_TIMEOUT_CONTEXT_VALUE
        );
        this.lambdaEnvironmentProps = {};

        console.log(props);

        //Create SSM documents
        if (SSMDocumentsDir) {
            const filesDir = readdirSync(SSMDocumentsDir);

            filesDir.map((fileName) => {
                const name = `${fileName.split('.')[0]}`;
                const ssmDocumentName = `SSMDocument-${name}`;

                const ssmConstruct = new CfnDocument(this, ssmDocumentName, {
                    documentFormat: 'JSON',
                    content: JSON.parse(this.getData(SSMDocumentsDir, fileName)),
                    documentType: 'Command',
                });
                this.lambdaEnvironmentProps[name.replace(HYPHEN, '_').toUpperCase()] =
                    ssmConstruct.ref;
            });

            this.lambdaEnvironmentProps[SSM_EXECUTION_TIMEOUT_ENV_VAR] =
                ssmExecutionTimeout;
        }
    }
    getData = (dir: string, file: string) =>
        readFileSync(path.join(__dirname, `./.${dir}/${file}`)).toString();
}
