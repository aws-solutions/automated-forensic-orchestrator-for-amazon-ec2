/* eslint-disable @typescript-eslint/no-non-null-assertion */
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
import { CfnMapping, CustomResource, Stack } from 'aws-cdk-lib';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Effect, IRole, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { Dashboard } from 'aws-cdk-lib/aws-cloudwatch';
import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import { APP_ACCOUNT_ASSUME_ROLE_NAME, TOOLS_AMI } from '../infra-utils/infra-types';

export interface ForensicsInvestigationProps {
    forensicDeadLetterQueue: IQueue;
    ebsEncryptionKeyID: string;
    subnetGroupName: string;
    instanceTable: ITable;
    vpc: IVpc;
    environment?: {
        [key: string]: string;
    };
    forensicBucket: IBucket;
    s3CopyRole: IRole;
    instanceProfileARN: string;
    instanceProfileRole: IRole;
    dashboard?: Dashboard;
    forensicApiResources?: string[];
    forensicImageName: string;
}

/**
 * Forensics investigation construct
 */
export class ForensicsInvestigationConstruct extends Construct {
    public createForensicInstanceLambda: IFunction;
    public checkInstanceStatusLambda: IFunction;
    public attachEBSSnapShotLambda: IFunction;
    public runMemoryAnalysisLambda: IFunction;
    public runForensicsCommandLambda: IFunction;
    public checkForensicInvestigationStatusLambda: IFunction;
    public terminateForensicInstanceLambda: IFunction;
    public forensicToolsLambda: IFunction;

    constructor(scope: Construct, id: string, props: ForensicsInvestigationProps) {
        super(scope, id);

        const region = Stack.of(this).region;
        const account = Stack.of(this).account;

        const createInstancePolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ssm:Describe*', 'ssm:Get*', 'ssm:List*'],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:CreateSecurityGroup'],
                resources: [`*`],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:Describe*', 'iam:Get*', 'iam:List*'],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:AttachVolume', 'ec2:DetachVolume'],
                resources: [
                    `arn:aws:ec2:${region}:${account}:volume/*`,
                    `arn:aws:ec2:${region}:${account}:instance/*`,
                ],
                conditions: {
                    StringEquals: {
                        'aws:ResourceTag/InstanceType': 'FORENSIC',
                    },
                },
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:RunInstances'],
                resources: [`*`],
                conditions: {
                    StringEquals: {
                        'ec2:Region': `${region}`,
                    },
                },
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:CreateTags'],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:Terminate*'],
                resources: [
                    `arn:aws:ec2:${region}:${account}:instance/*`,
                    `arn:aws:ec2:${region}:${account}:client-vpn-endpoint/*`,
                ],
                conditions: {
                    StringEquals: {
                        'ec2:ResourceTag/InstanceType': 'FORENSIC',
                    },
                },
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['iam:PassRole'],
                resources: [props.instanceProfileRole.roleArn],
            }),
        ];

        const additionalPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:CreateVolume'],
                resources: [`arn:aws:ec2:${region}:${account}:volume/*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:AttachVolume'],
                resources: [
                    `arn:aws:ec2:${region}:${account}:instance/*`,
                    `arn:aws:ec2:${region}:${account}:volume/*`,
                ],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:Describe*'],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ssm:SendCommand', 'ssm:GetDocument'],
                resources: [
                    `arn:aws:s3:::*`,
                    `arn:aws:ssm:*:*:association/*`,
                    `arn:aws:ssm:*:*:document/*`,
                    `arn:aws:ec2:*:*:instance/*`,
                    `arn:aws:ssm:*:*:managed-instance/*`,
                ],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'ssm:ListCommands',
                    'ssm:ListDocuments',
                    'ssm:ListCommandInvocations',
                    'ssm:GetCommandInvocation',
                ],
                resources: [`*`],
            }),
        ];

        const investigationAdditionalPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ssm:SendCommand', 'ssm:GetDocument'],
                resources: [
                    `arn:aws:s3:::*`,
                    `arn:aws:ssm:*:*:association/*`,
                    `arn:aws:ssm:*:*:document/*`,
                    `arn:aws:ec2:*:*:instance/*`,
                    `arn:aws:ssm:*:*:managed-instance/*`,
                ],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ssm:SendCommand', 'ssm:GetDocument'],
                resources: [
                    `arn:aws:s3:::*`,
                    `arn:aws:ssm:*:*:association/*`,
                    `arn:aws:ssm:*:*:document/*`,
                    `arn:aws:ec2:*:*:instance/*`,
                    `arn:aws:ssm:*:*:managed-instance/*`,
                ],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'ssm:ListCommands',
                    'ssm:ListDocuments',
                    'ssm:ListCommandInvocations',
                    'ssm:GetCommandInvocation',
                ],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'dynamodb:ListCommands',
                    'ssm:Describe*',
                    'ssm:Get*',
                    'ssm:List*',
                ],
                resources: [`*`],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['sts:AssumeRole'],
                resources: [props.s3CopyRole.roleArn],
            }),
        ];
        if (props.forensicApiResources) {
            createInstancePolicies.push(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ['appsync:GraphQL'],
                    resources: props.forensicApiResources,
                })
            );
            investigationAdditionalPolicies.push(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ['appsync:GraphQL'],
                    resources: props.forensicApiResources,
                })
            );
            additionalPolicies.push(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ['appsync:GraphQL'],
                    resources: props.forensicApiResources,
                })
            );
        }

        //-------------------------------------------------------------------------
        // Lambda - Function to create forensic instance
        //-------------------------------------------------------------------------
        this.createForensicInstanceLambda = new PythonLambdaConstruct(
            this,
            'createForensicInstance',
            {
                handler: 'src.investigation.createForensicInstance.handler',
                applicationName: 'createForensicInstance',
                functionName: 'Fo-createForensicInstance',
                environment: {
                    ...props.environment,
                    FORENSIC_INSTANCE_PROFILE: props.instanceProfileARN,
                    VPC_ID: props.vpc.vpcId,
                    FORENSIC_AMI_NAME: props.forensicImageName,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                },
                initialPolicy: [...createInstancePolicies],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        props.instanceTable.grantReadWriteData(this.createForensicInstanceLambda);

        //-------------------------------------------------------------------------
        // Lambda - Function to terminate forensic instance
        //-------------------------------------------------------------------------
        this.terminateForensicInstanceLambda = new PythonLambdaConstruct(
            this,
            'terminateForensicInstance',
            {
                handler: 'src.investigation.terminateForensicInstance.handler',
                applicationName: 'terminateForensicInstance',
                functionName: 'Fo-terminateForensicInstance',
                environment: {
                    ...props.environment,
                    VPC_ID: props.vpc.vpcId,
                },
                initialPolicy: [...createInstancePolicies],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        props.instanceTable.grantReadWriteData(this.terminateForensicInstanceLambda);

        //-------------------------------------------------------------------------
        // Lambda - Function to check instance status (Is SSM installed and ready for forensics
        //-------------------------------------------------------------------------
        this.checkInstanceStatusLambda = new PythonLambdaConstruct(
            this,
            'checkInstanceStatus',
            {
                handler: 'src.investigation.checkInstanceStatus.handler',
                applicationName: 'checkInstanceStatus',
                functionName: 'Fo-checkInstanceStatus',
                initialPolicy: [...createInstancePolicies],
                dashboard: props.dashboard,
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                },
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        props.instanceTable.grantReadWriteData(this.checkInstanceStatusLambda);

        //-------------------------------------------------------------------------
        // Lambda - Function to attach EBS snapshot to the forensic instance
        //-------------------------------------------------------------------------
        this.attachEBSSnapShotLambda = new PythonLambdaConstruct(
            this,
            'attachEBSSnapShot',
            {
                handler: 'src.investigation.attachEBSSnapShot.handler',
                applicationName: 'attachEBSSnapShot',
                functionName: 'Fo-attachEBSSnapShot',
                environment: {
                    MOUNT_VOLUME_SSM_DOCUMENT_ID: props.environment
                        ? props.environment['dev']
                        : '',
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    VOLUME_ENCRYPTION_KEY_ID: props.ebsEncryptionKeyID,
                    ...(props.environment && {
                        VOLUME_MOUNT_CMD_ID:
                            props.environment['LINUX_DISK_INVESTIGATION_PREPARE'],
                    }),
                },
                initialPolicy: [...additionalPolicies],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        props.instanceTable.grantReadWriteData(this.attachEBSSnapShotLambda);

        //-------------------------------------------------------------------------
        // Lambda - Function to run memory analysis
        //-------------------------------------------------------------------------
        this.runMemoryAnalysisLambda = new PythonLambdaConstruct(
            this,
            'runMemoryAnalysis',
            {
                handler: 'src.investigation.runMemoryAnalysis.handler',
                applicationName: 'runMemoryAnalysis',
                functionName: 'Fo-runMemoryAnalysis',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    S3_COPY_ROLE: props.s3CopyRole.roleArn,
                },
                initialPolicy: [
                    ...investigationAdditionalPolicies,
                    ...createInstancePolicies,
                ],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        props.instanceTable.grantReadWriteData(this.runMemoryAnalysisLambda);

        this.runMemoryAnalysisLambda.role?.grantPassRole(props.s3CopyRole);

        props.forensicBucket.grantReadWrite(this.runMemoryAnalysisLambda.role!);

        //-------------------------------------------------------------------------
        // Lambda - Function to run forensic command (Memory and Disk)
        //-------------------------------------------------------------------------
        this.runForensicsCommandLambda = new PythonLambdaConstruct(
            this,
            'runForensicsCommand',
            {
                handler: 'src.investigation.runForensicsCommand.handler',
                applicationName: 'runForensicsCommand',
                functionName: 'Fo-runForensicsCommand',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    S3_COPY_ROLE: props.s3CopyRole.roleArn,
                },
                initialPolicy: [
                    ...investigationAdditionalPolicies,
                    ...createInstancePolicies,
                ],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        props.instanceTable.grantReadWriteData(this.runForensicsCommandLambda);
        this.runForensicsCommandLambda.role?.grantPassRole(props.s3CopyRole);

        //-------------------------------------------------------------------------
        // Lambda - Check forensic investigation is complete
        //-------------------------------------------------------------------------
        this.checkForensicInvestigationStatusLambda = new PythonLambdaConstruct(
            this,
            'checkForensicInvestigationStatus',
            {
                handler: 'src.investigation.checkForensicInvestigationStatus.handler',
                applicationName: 'checkForensicInvestigationStatus',

                functionName: 'Fo-checkForensicInvestigationStatus',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    S3_COPY_ROLE: props.s3CopyRole.roleArn,
                },
                initialPolicy: [
                    ...investigationAdditionalPolicies,
                    ...createInstancePolicies,
                ],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        props.instanceTable.grantReadWriteData(
            this.checkForensicInvestigationStatusLambda
        );
        props.forensicBucket.grantRead(this.checkForensicInvestigationStatusLambda);

        //-------------------------------------------------------------------------
        // Lambda - lambda function to run SSM document to upload forensics tools and create profiles
        //-------------------------------------------------------------------------

        const toolsAMI: {
            [k1: string]: {
                [k2: string]: any;
            };
        } = this.node.tryGetContext(TOOLS_AMI);

        const toolsAMITable = new CfnMapping(this, 'tools-ami-table', {
            mapping: toolsAMI,
        });

        const amiID: string = toolsAMITable.findInMap(Stack.of(this).region, 'amiID');

        this.forensicToolsLambda = new PythonLambdaConstruct(
            this,
            'forensicToolsLambda',
            {
                handler: 'src.loadforensictools.loadForensicTools.handler',
                applicationName: 'forensicToolsLambda',
                functionName: 'Fo-forensicToolsLambda',
                environment: {
                    ...props.environment,
                    AMI_ID: amiID,
                    VPC_ID: props.vpc.vpcId,
                    FORENSIC_INSTANCE_PROFILE: props.instanceProfileARN,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    S3_COPY_ROLE: props.s3CopyRole.roleArn,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                initialPolicy: [
                    ...createInstancePolicies,
                    ...investigationAdditionalPolicies,
                ],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        this.forensicToolsLambda.role?.grantPassRole(props.s3CopyRole);

        // Note: Id is max 20 characters
        new CustomResource(this, 'Custom Tools Action', {
            serviceToken: this.forensicToolsLambda.functionArn,
            resourceType: 'Custom::ActionTarget',
            properties: {
                Name: 'Forensic Tools Loader',
                Description: 'Trigger Forensic Tools loader Action',
                Id: 'ForensicLoaderAction',
            },
        });
    }
}
