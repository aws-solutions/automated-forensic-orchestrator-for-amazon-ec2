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

import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import * as path from 'path';
import { Construct } from 'constructs';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Effect, IRole, Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { Dashboard } from 'aws-cdk-lib/aws-cloudwatch';
import { Stack } from 'aws-cdk-lib';
import { APP_ACCOUNT_ASSUME_ROLE_NAME } from '../infra-utils/infra-types';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import { addIAMPolicyCfnNagSuppressor } from '../infra-utils/cfn-nag-suppression';

export interface ForensicsAcquisitionProps {
    instanceProfileARN: string;

    forensicDeadLetterQueue: IQueue;
    appAccountKMSKeyAlias: string;
    subnetGroupName: string;
    instanceTable: ITable;
    vpc: IVpc;
    forensicBucket: IBucket;
    s3CopyRole: IRole;
    environment?: {
        [key: string]: string;
    };
    dashboard?: Dashboard;
    forensicApiResources?: string[];
    applicationAccounts?: string[];
}

/**
 * Forensics acquisition construct
 */
export class ForensicsAcquisitionConstruct extends Construct {
    public performDiskAcquisitionSetupLambda: IFunction;

    public performInstanceIsolationLambda: IFunction;

    public performInstanceSnapShotLambda: IFunction;

    public snapShotCompletionCheckerLambda: IFunction;

    public shareSnapShotLambda: IFunction;

    public performSnapshotCopyLambda: IFunction;

    public snapshotCopyCheckerLambda: IFunction;

    public runMemoryAcquisitionLambda: IFunction;

    public checkMemoryAcquisitionCompletionLambda: IFunction;

    private readonly LAMBDA_RELATIVE_PATH = '../../lambda';

    constructor(scope: Construct, id: string, props: ForensicsAcquisitionProps) {
        super(scope, id);
        const listOfApplicationAccountIds = props.applicationAccounts?.map(
            (accountId) =>
                `arn:aws:iam::${accountId}:role/${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                    Stack.of(this).region
                }`
        );

        const assumeRolePolicyStateMent = new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['sts:AssumeRole'],
            resources: listOfApplicationAccountIds,
        });
        const assumeRoleIAMPolicy = new Policy(this, 'assumeRoleIAMPolicy', {});
        assumeRoleIAMPolicy.addStatements(assumeRolePolicyStateMent);
        addIAMPolicyCfnNagSuppressor(assumeRoleIAMPolicy);

        //-------------------------------------------------------------------------
        // Lambda - Perform Disk Acquisition
        //-------------------------------------------------------------------------
        this.performDiskAcquisitionSetupLambda = new PythonLambdaConstruct(
            this,
            'acquisitionInitialiser',
            {
                handler: 'src.acquisition.acquisitionInitialiser.handler',
                applicationName: 'acquisitionInitialiser',

                functionName: 'Fo-acquisitionInitialiser',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                dashboard: props.dashboard,

                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        assumeRoleIAMPolicy.attachToRole(this.performDiskAcquisitionSetupLambda.role!);

        props.instanceTable.grantReadWriteData(this.performDiskAcquisitionSetupLambda);

        //-------------------------------------------------------------------------
        // Lambda - Perform Disk Isolation in Compromised instance
        //-------------------------------------------------------------------------
        this.performInstanceIsolationLambda = new PythonLambdaConstruct(
            this,
            'instanceIsolation',
            {
                handler: 'src.acquisition.performIsolation.handler',
                applicationName: 'performIsolation',

                functionName: 'Fo-performIsolation',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                dashboard: props.dashboard,

                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        assumeRoleIAMPolicy.attachToRole(this.performInstanceIsolationLambda.role!);
        props.instanceTable.grantReadWriteData(this.performInstanceIsolationLambda);
        //-------------------------------------------------------------------------
        // Lambda - Perform Instance Snapshot in Compromised instance
        //-------------------------------------------------------------------------
        this.performInstanceSnapShotLambda = new PythonLambdaConstruct(
            this,
            'instanceSnapshot',
            {
                handler: 'src.acquisition.performInstanceSnapshot.handler',
                applicationName: 'performInstanceSnapshot',
                functionName: 'Fo-performInstanceSnapshot',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        assumeRoleIAMPolicy.attachToRole(this.performInstanceSnapShotLambda.role!);

        props.instanceTable.grantReadWriteData(this.performInstanceSnapShotLambda);

        //-------------------------------------------------------------------------
        // Lambda - Check Snapshot is complete
        //-------------------------------------------------------------------------
        this.snapShotCompletionCheckerLambda = new PythonLambdaConstruct(
            this,
            'checkSnapShotStatus',
            {
                handler: 'src.acquisition.checkSnapShotStatus.handler',
                applicationName: 'checkSnapShotStatus',
                functionName: 'Fo-checkSnapShotStatus',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        assumeRoleIAMPolicy.attachToRole(this.snapShotCompletionCheckerLambda.role!);
        props.instanceTable.grantReadWriteData(this.snapShotCompletionCheckerLambda);

        //-------------------------------------------------------------------------
        // Lambda - Share snapshot with Forensic Account
        //-------------------------------------------------------------------------
        this.shareSnapShotLambda = new PythonLambdaConstruct(this, 'shareSnapShot', {
            handler: 'src.acquisition.shareSnapShot.handler',
            applicationName: 'shareSnapShot',
            functionName: 'Fo-shareSnapShotFn',
            environment: {
                ...props.environment,
                INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                    Stack.of(this).region
                }`,
            },
            dashboard: props.dashboard,
            vpc: props.vpc,
            deadLetterQueue: props.forensicDeadLetterQueue,
        }).function;

        assumeRoleIAMPolicy.attachToRole(this.shareSnapShotLambda.role!);

        props.instanceTable.grantReadWriteData(this.shareSnapShotLambda);

        const additionalSnapshotCopyPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'ec2:CreateSnapshots',
                    'ec2:CreateSnapshot',
                    'ec2:CreateTags',
                    'ec2:CopySnapshot',
                ],
                resources: [
                    'arn:aws:ec2:*::snapshot/*',
                    'arn:aws:ec2:*::volume/*',
                    'arn:aws:ec2:*::instance/*',
                ],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:DescribeSnapshot'],
                resources: ['arn:aws:ec2:*::snapshot/*'],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:DescribeSnapshots', 'ec2:DescribeSnapshotTierStatus'],
                resources: ['*'],
            }),
        ];

        const additionalSnapshotCopyIAMPolicy = new Policy(
            this,
            'additionalSnapshotCopyIAMPolicy'
        );
        additionalSnapshotCopyIAMPolicy.addStatements(...additionalSnapshotCopyPolicies);
        addIAMPolicyCfnNagSuppressor(additionalSnapshotCopyIAMPolicy);

        //-------------------------------------------------------------------------
        // Lambda - Perform Snapshot copy of shared snapshot from Compromised instance
        //-------------------------------------------------------------------------
        this.performSnapshotCopyLambda = new PythonLambdaConstruct(this, 'snapshotCopy', {
            handler: 'src.copysnapshot.performCopySnapshot.handler',
            applicationName: 'snapshotCopy',

            functionName: 'Fo-performCopySnapshot',
            sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
            dashboard: props.dashboard,

            environment: {
                ...props.environment,
                APP_FORENSIC_EBS_KEY_ALIAS: props.appAccountKMSKeyAlias,
                INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                    Stack.of(this).region
                }`,
            },
            vpc: props.vpc,
            deadLetterQueue: props.forensicDeadLetterQueue,
        }).function;
        additionalSnapshotCopyIAMPolicy.attachToRole(
            this.performSnapshotCopyLambda.role!
        );
        assumeRoleIAMPolicy.attachToRole(this.performSnapshotCopyLambda.role!);

        props.instanceTable.grantReadWriteData(this.performSnapshotCopyLambda);

        //-------------------------------------------------------------------------
        // Lambda - Check Snapshot copy is complete
        //-------------------------------------------------------------------------
        this.snapshotCopyCheckerLambda = new PythonLambdaConstruct(
            this,
            'snapshotCopyChecker',
            {
                handler: 'src.copysnapshot.checkCopySnapShotStatus.handler',
                applicationName: 'snapshotCopyChecker',
                functionName: 'Fo-snapshotCopyChecker',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        additionalSnapshotCopyIAMPolicy.attachToRole(
            this.snapshotCopyCheckerLambda.role!
        );
        assumeRoleIAMPolicy.attachToRole(this.snapshotCopyCheckerLambda.role!);
        props.instanceTable.grantReadWriteData(this.snapshotCopyCheckerLambda);

        const memoryAcquisitionAdditionalPolicies = [
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
                actions: ['ssm:ModifyDocumentPermission'],
                resources: [`arn:aws:ssm:*:*:document/*`],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ssm:Describe*', 'ssm:Get*', 'ssm:List*'],
                resources: [`*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['dynamodb:ListCommands'],
                resources: [`*`],
            }),

            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['sts:AssumeRole'],
                resources: [props.s3CopyRole.roleArn],
            }),
        ];

        const memoryAcquisitionAdditionalIAMPolicy = new Policy(
            this,
            'memoryAcquisitionAdditionalIAMPolicy'
        );
        memoryAcquisitionAdditionalIAMPolicy.addStatements(
            ...memoryAcquisitionAdditionalPolicies
        );

        addIAMPolicyCfnNagSuppressor(memoryAcquisitionAdditionalIAMPolicy);
        //-------------------------------------------------------------------------
        // Lambda - Assume role to Compromised instance and run memory acquisition
        //-------------------------------------------------------------------------
        this.runMemoryAcquisitionLambda = new PythonLambdaConstruct(
            this,
            'runMemoryAcquisitionLambda',
            {
                handler: 'src.acquisition.performMemoryAcquisition.handler',
                applicationName: 'memoryAcquisition',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                functionName: 'Fo-performMemoryAcquisition',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    S3_COPY_ROLE: props.s3CopyRole.roleArn,
                    //TODO - update as props
                    memoryAcquisitionDocumentName: 'lime-memory-acquisition',
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        memoryAcquisitionAdditionalIAMPolicy.attachToRole(
            this.runMemoryAcquisitionLambda.role!
        );
        assumeRoleIAMPolicy.attachToRole(this.runMemoryAcquisitionLambda.role!);

        this.runMemoryAcquisitionLambda.role?.grantPassRole(props.s3CopyRole);
        props.instanceTable.grantReadWriteData(this.runMemoryAcquisitionLambda);

        this.checkMemoryAcquisitionCompletionLambda = new PythonLambdaConstruct(
            this,
            'checkMemoryAcquisition',
            {
                handler: 'src.acquisition.checkMemoryAcquisition.handler',
                applicationName: 'checkMemoryAcquisition',
                sourceCodePath: path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH),
                functionName: 'Fo-checkMemoryAcquisition',
                environment: {
                    ...props.environment,
                    S3_BUCKET_NAME: props.forensicBucket.bucketName,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        memoryAcquisitionAdditionalIAMPolicy.attachToRole(
            this.checkMemoryAcquisitionCompletionLambda.role!
        );

        assumeRoleIAMPolicy.attachToRole(
            this.checkMemoryAcquisitionCompletionLambda.role!
        );
        props.instanceTable.grantReadWriteData(
            this.checkMemoryAcquisitionCompletionLambda
        );

        props.forensicBucket.grantRead(this.checkMemoryAcquisitionCompletionLambda);

        if (props.forensicApiResources) {
            const appSyncNotifyMutationPolicy = new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['appsync:GraphQL'],
                resources: props.forensicApiResources,
            });

            const appSyncNotifyMutationIAMPolicy = new Policy(
                this,
                'appSyncNotifyMutationIAMPolicy'
            );
            appSyncNotifyMutationIAMPolicy.addStatements(appSyncNotifyMutationPolicy);
            addIAMPolicyCfnNagSuppressor(appSyncNotifyMutationIAMPolicy);

            appSyncNotifyMutationIAMPolicy.attachToRole(
                this.checkMemoryAcquisitionCompletionLambda.role!
            );

            appSyncNotifyMutationIAMPolicy.attachToRole(
                this.runMemoryAcquisitionLambda.role!
            );

            appSyncNotifyMutationIAMPolicy.attachToRole(
                this.snapShotCompletionCheckerLambda.role!
            );

            appSyncNotifyMutationIAMPolicy.attachToRole(this.shareSnapShotLambda.role!);

            appSyncNotifyMutationIAMPolicy.attachToRole(
                this.performInstanceSnapShotLambda.role!
            );

            appSyncNotifyMutationIAMPolicy.attachToRole(
                this.performDiskAcquisitionSetupLambda.role!
            );
        }
    }
}
