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
import { CustomResource } from 'aws-cdk-lib';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { Dashboard } from 'aws-cdk-lib/aws-cloudwatch';
import * as path from 'path';
import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { IQueue } from 'aws-cdk-lib/aws-sqs';

export interface ForensicsCustomActionNStackProps {
    forensicDeadLetterQueue: IQueue;
    subnetGroupName: string;
    vpc: IVpc;
    environment?: {
        [key: string]: string;
    };
    dashboard?: Dashboard;
}

/**
 * Forensics security hub action construct
 */
export class ForensicsSecurityHubActionConstruct extends Construct {
    public customAction: CustomResource;

    public customSecurityHubAction: CustomResource;

    public customActionFunction: IFunction;

    private readonly LAMBDA_RELATIVE_PATH = '../../lambda';

    constructor(scope: Construct, id: string, props: ForensicsCustomActionNStackProps) {
        super(scope, id);
        //-------------------------------------------------------------------------
        // Custom Lambda Policy
        //
        const createCustomActionPolicy = new Policy(this, 'createCustomActionPolicy', {
            policyName: 'forensic_Custom_Action',
            statements: [
                new PolicyStatement({
                    actions: [
                        'logs:CreateLogGroup',
                        'logs:CreateLogStream',
                        'logs:PutLogEvents',
                    ],
                    resources: ['*'],
                }),
                new PolicyStatement({
                    actions: [
                        'securityhub:CreateActionTarget',
                        'securityhub:DeleteActionTarget',
                    ],
                    resources: ['*'],
                }),
            ],
        });

        //-------------------------------------------------------------------------
        // Custom Lambda - Create Custom Action
        //
        const customActionFunction = new PythonLambdaConstruct(
            this,
            'instanceIsolation',
            {
                handler: 'src.customaction.createCustomAction.lambda_handler',
                applicationName: 'createCustomAction',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                dashboard: props.dashboard,
                environment: {
                    ...props.environment,
                },
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        );
        this.customActionFunction = customActionFunction.function;

        customActionFunction.function.role?.attachInlinePolicy(createCustomActionPolicy);

        // Note: Id is max 20 characters
        this.customAction = new CustomResource(this, 'Custom Action', {
            serviceToken: customActionFunction.function.functionArn,
            resourceType: 'Custom::ActionTarget',
            properties: {
                Name: 'Forensic Triage',
                Description: 'Trigger Forensic Triage Action',
                Id: 'ForensicTriageAction',
            },
        });

        this.customSecurityHubAction = new CustomResource(
            this,
            'Custom Isolation Action',
            {
                serviceToken: customActionFunction.function.functionArn,
                resourceType: 'Custom::ActionTarget',
                properties: {
                    Name: 'ForensicIsolation',
                    Description: 'Trigger Forensic Triage Isolation Action',
                    Id: 'ForensicIsolateAct',
                },
            }
        );
    }
}
