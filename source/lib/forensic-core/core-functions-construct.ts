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
import { Stack } from 'aws-cdk-lib';
import { Dashboard } from 'aws-cdk-lib/aws-cloudwatch';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { IVpc, SecurityGroup } from 'aws-cdk-lib/aws-ec2';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';
import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import { APP_ACCOUNT_ASSUME_ROLE_NAME } from '../infra-utils/infra-types';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import { addIsolationCfnSecurityGroup } from '../infra-utils/cfn-nag-suppression';

export interface ForensicsCoreProps {
    forensicDeadLetterQueue: IQueue;
    subnetGroupName: string;
    instanceTable: ITable;
    vpc: IVpc;
    notificationTopic: ITopic;
    notificationTopicEncryptionKey: IKey;
    applicationAccounts?: string[];
    dashboard?: Dashboard;
    forensicApiResources?: string[];
    environment?: {
        [key: string]: string;
    };
}

/**
 * Forensics core
 */
export class ForensicsCore extends Construct {
    public triageLambda: IFunction;
    public sendNotificationLambda: IFunction;
    public sendErrorNotificationLambda: IFunction;
    public isolationLambda: IFunction;

    constructor(scope: Construct, id: string, props: ForensicsCoreProps) {
        super(scope, id);

        const allAllTrafficSG = new SecurityGroup(this, 'IsolationSecurityGroup', {
            vpc: props.vpc,
            description: 'Allow ssh access to ec2 instances',
        });
        //   https://www.youtube.com/watch?v=pPCuCYrhIyI proper way to isolate instance
        //  by covert all traffic to untracked https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html
        allAllTrafficSG.addIngressRule(
            ec2.Peer.anyIpv4(),
            ec2.Port.allTraffic(),
            'allow all'
        );

        const noRuleSG = new SecurityGroup(this, 'IsolationSecurityGroupNoRule', {
            vpc: props.vpc,
            description: 'No rule security group',
            allowAllOutbound: false,
        });
        addIsolationCfnSecurityGroup(noRuleSG);
        addIsolationCfnSecurityGroup(allAllTrafficSG);

        const additionalPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'ec2:DescribeInstances',
                    'ec2:DescribeImages',
                    'ec2:DescribeTags',
                    'ec2:DescribeSnapshots',
                ],
                // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-ec2-console.html no resource level limit is supported
                resources: [`*`],
            }),
        ];
        const listOfApplicationAccountIds = props.applicationAccounts?.map(
            (accountId) =>
                `arn:aws:iam::${accountId}:role/${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                    Stack.of(this).region
                }`
        );

        if (listOfApplicationAccountIds) {
            additionalPolicies.push(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ['sts:AssumeRole'],
                    resources: listOfApplicationAccountIds,
                })
            );
        }

        const isolationPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'ec2:CreateSecurityGroup',
                    'ec2:DescribeSecurityGroups',
                    'ec2:AuthorizeSecurityGroupIngress',
                    'ec2:RevokeSecurityGroupIngress',
                    'ec2:AuthorizeSecurityGroupEgress',
                    'ec2:RevokeSecurityGroupEgress',
                    'ec2:ModifySecurityGroupRules',
                    'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
                    'ec2:UpdateSecurityGroupRuleDescriptionsEgress',
                ],
                resources: [`arn:aws:ec2:${Stack.of(this).region}:*:*`],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['ec2:ModifySecurityGroupRules'],
                resources: [
                    `arn:aws:ec2:${Stack.of(this).region}:*:security-group-rule/*`,
                ],
            }),
        ];
        //-------------------------------------------------------------------------
        // Lambda - lambda function isolate the compromised instance by attaching securitygroups with no egress and ingress
        //-------------------------------------------------------------------------
        this.isolationLambda = new PythonLambdaConstruct(
            this,
            'IsolateForensicInstance',
            {
                handler: 'src.isolation.isolateEc2.handler',
                applicationName: 'isolateForensicEc2Instance',
                functionName: 'Fo-isolateEc2Instance',
                environment: {
                    ...props.environment,
                    VPC_ID: props.vpc.vpcId,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    FORENSIC_ISOLATION_SG: allAllTrafficSG.securityGroupId,
                    FORENSIC_ISOLATION_SG_NO_RULE: noRuleSG.securityGroupId,
                    APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                        Stack.of(this).region
                    }`,
                },
                skipCodeSigning: true,
                initialPolicy: [...additionalPolicies, ...isolationPolicies],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        props.instanceTable.grantReadWriteData(this.isolationLambda);

        if (props.forensicApiResources) {
            additionalPolicies.push(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ['appsync:GraphQL'],
                    resources: props.forensicApiResources,
                })
            );
        }

        //-------------------------------------------------------------------------
        // Lambda - Function to triage the instance
        //-------------------------------------------------------------------------
        this.triageLambda = new PythonLambdaConstruct(this, 'getInstanceFunction', {
            handler: 'src.triage.app.lambda_handler',
            applicationName: 'triage',
            functionName: 'Fo-triage',
            environment: {
                ...props.environment,
                INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                APP_ACCOUNT_ROLE: `${APP_ACCOUNT_ASSUME_ROLE_NAME}-${
                    Stack.of(this).region
                }`,
            },
            skipCodeSigning: true,
            initialPolicy: [...additionalPolicies],
            dashboard: props.dashboard,
            vpc: props.vpc,
            deadLetterQueue: props.forensicDeadLetterQueue,
        }).function;

        //-------------------------------------------------------------------------
        // Lambda - Function to send notification
        //-------------------------------------------------------------------------
        this.sendNotificationLambda = new PythonLambdaConstruct(
            this,
            'sendNotificationLambda',
            {
                handler: 'src.notification.sendNotification.handler',
                applicationName: 'sendNotification',

                functionName: 'Fo-sendNotification',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    NOTIFICATION_TOPIC_ARN: props.notificationTopic.topicArn,
                },
                dashboard: props.dashboard,
                initialPolicy: [
                    new PolicyStatement({
                        resources: [props.notificationTopic.topicArn],
                        actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                        effect: Effect.ALLOW,
                    }),
                    new PolicyStatement({
                        resources: [props.notificationTopicEncryptionKey.keyArn],
                        actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                        effect: Effect.ALLOW,
                    }),
                ],
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        props.instanceTable.grantReadWriteData(this.sendNotificationLambda);

        props.notificationTopicEncryptionKey.grantEncryptDecrypt(
            this.sendNotificationLambda
        );
        props.notificationTopic.grantPublish(this.sendNotificationLambda);

        //-------------------------------------------------------------------------
        // Lambda - Function to send error notification
        //-------------------------------------------------------------------------
        this.sendErrorNotificationLambda = new PythonLambdaConstruct(
            this,
            'sendErrorNotificationLambda',
            {
                handler: 'src.notification.sendErrorNotification.handler',
                applicationName: 'sendErrorNotification',

                functionName: 'Fo-sendErrorNotification',
                environment: {
                    ...props.environment,
                    INSTANCE_TABLE_NAME: props.instanceTable.tableName,
                    NOTIFICATION_TOPIC_ARN: props.notificationTopic.topicArn,
                },
                dashboard: props.dashboard,
                initialPolicy: [
                    new PolicyStatement({
                        resources: [props.notificationTopic.topicArn],
                        actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                        effect: Effect.ALLOW,
                    }),
                    new PolicyStatement({
                        resources: [props.notificationTopicEncryptionKey.keyArn],
                        actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                        effect: Effect.ALLOW,
                    }),
                ],
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        props.instanceTable.grantReadWriteData(this.sendErrorNotificationLambda);

        props.notificationTopicEncryptionKey.grantEncryptDecrypt(
            this.sendErrorNotificationLambda
        );
        props.notificationTopic.grantPublish(this.sendErrorNotificationLambda);
    }
}
