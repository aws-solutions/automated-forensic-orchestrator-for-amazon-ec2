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
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { IVpc, SecurityGroup } from 'aws-cdk-lib/aws-ec2';
import {
    CfnInstanceProfile,
    Effect,
    ManagedPolicy,
    PolicyStatement,
    Role,
    ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import { addIsolationCfnSecurityGroup } from '../infra-utils/cfn-nag-suppression';
import {
    APP_ACCOUNT_ASSUME_ROLE_NAME,
    FORENSIC_ISOLATION_PROFILE_NAME,
} from '../infra-utils/infra-types';
import { NagSuppressions } from 'cdk-nag';

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
    public checkAcquisitionLambda: IFunction;
    public sendNotificationLambda: IFunction;
    public sendErrorNotificationLambda: IFunction;
    public isolationLambda: IFunction;

    constructor(scope: Construct, id: string, props: ForensicsCoreProps) {
        super(scope, id);

        const allAllTrafficSG = new SecurityGroup(this, 'IsolationSecurityGroup', {
            vpc: props.vpc,
            description: 'Allow ssh access to ec2 instances',
        });
        /**
         * An all-traffic ingress rule from any IPv4 address, on purpose.
         *
         * This security group is never used to *permit* access. Attaching a rule
         * that matches all traffic converts an instance's existing flows from
         * tracked to untracked, which makes the kernel drop the established
         * connections instead of letting them continue after the isolation group
         * is swapped in. Without it, an attacker's existing SSH or C2 session
         * survives isolation until it happens to time out.
         *
         * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html
         *
         * It is applied only as an intermediate step by the isolation Lambda, on
         * an instance that is being cut off, and the group it is replaced with
         * (noRuleSG below) has no rules at all. The residual exposure is the
         * window between the two swaps, on an instance already believed
         * compromised, in a VPC the customer controls.
         *
         * Narrowing the CIDR to the VPC range would not achieve the same thing:
         * connection tracking is only bypassed when the rule matches all traffic.
         */
        allAllTrafficSG.addIngressRule(
            ec2.Peer.anyIpv4(),
            ec2.Port.allTraffic(),
            'allow all: converts existing flows to untracked so isolation drops them'
        );
        NagSuppressions.addResourceSuppressions(allAllTrafficSG, [
            {
                id: 'AwsSolutions-EC23',
                reason:
                    'Deliberate. An all-traffic rule is the documented way to move an '
                    + 'instance\'s existing connections from tracked to untracked so that '
                    + 'isolation terminates them rather than leaving an attacker\'s session '
                    + 'established. See the connection-tracking documentation linked above. '
                    + 'The group is applied only transiently by the isolation Lambda to an '
                    + 'instance being contained, and is replaced by a group with no rules. '
                    + 'Narrowing the CIDR would defeat the mechanism.',
            },
        ]);

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
                    'ec2:ModifyInstanceAttribute',
                    'ec2:AssociateIamInstanceProfile',
                    'ec2:DescribeIamInstanceProfileAssociations',
                    'ec2:ReplaceIamInstanceProfileAssociation',
                    'ec2:DescribeAddresses',
                    'ec2:DisassociateAddress',
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
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['iam:GetInstanceProfile'],
                resources: [`arn:aws:iam::${Stack.of(this).account}:instance-profile/*`],
            }),
            /**
             * iam:PutRolePolicy on every role in the account, deliberately.
             *
             * Isolation attaches a deny-all inline policy to the instance
             * profile role of the compromised instance, which revokes that
             * instance's AWS access immediately rather than waiting for its
             * credentials to expire. Which role that is depends on which
             * instance turns out to be compromised, so it is not known when this
             * stack is deployed - and IAM offers no condition key for the inline
             * policy name, so there is nothing narrower to scope to.
             *
             * Residual risk, stated rather than hidden: a principal able to
             * invoke this Lambda can cause an inline policy to be written onto
             * any role in this account. Control who may invoke it, and alert on
             * iam:PutRolePolicy in CloudTrail. Removing the permission removes
             * the credential-revocation step from isolation, leaving the
             * instance's role usable until its session expires.
             */
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['iam:PutRolePolicy'],
                resources: [`arn:aws:iam::${Stack.of(this).account}:role/*`],
            }),
        ];
        //-------------------------------------------------------------------------
        // Lambda - lambda function isolate the compromised instance by attaching securitygroups with no egress and ingress
        //-------------------------------------------------------------------------
        const isolationInstanceRole = new Role(this, 'IsolationInstanceRole', {
            assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
            path: '/',
        });

        isolationInstanceRole.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('AWSDenyAll')
        );

        //Builds the instance Profile to be attached to EC2 instance created during image building
        const solutionAccountIsolationProfileName = `ForensicIsolationInstanceProfile-${
            Stack.of(this).region
        }`;
        const isolationProfile = new CfnInstanceProfile(
            this,
            'ForensicIsolationInstanceProfile',
            {
                roles: [isolationInstanceRole.roleName],
                instanceProfileName: `ForensicIsolationInstanceProfile-${
                    Stack.of(this).region
                }`,
            }
        );

        const isolationProfileName =
            this.node.tryGetContext(FORENSIC_ISOLATION_PROFILE_NAME) ||
            'ForensicIsolationInstanceProfile';
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
                    FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME: isolationProfileName,
                    SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME:
                        solutionAccountIsolationProfileName,
                },
                initialPolicy: [...additionalPolicies, ...isolationPolicies],
                dashboard: props.dashboard,
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;
        this.isolationLambda.role?.grantPassRole(isolationInstanceRole);
        props.instanceTable.grantReadWriteData(this.isolationLambda);
        isolationProfile.node.addDependency(this.isolationLambda);

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
            initialPolicy: [...additionalPolicies],
            dashboard: props.dashboard,
            vpc: props.vpc,
            deadLetterQueue: props.forensicDeadLetterQueue,
        }).function;

        //-------------------------------------------------------------------------
        // Lambda - Function to Check the instance Acquisition requirement
        //-------------------------------------------------------------------------
        this.checkAcquisitionLambda = new PythonLambdaConstruct(this, 'checkAcquisitionFunction', {
            // The module file is checkacquisition.py, all lower case. Declaring
            // checkAcquisition here resolved on a case-insensitive developer
            // filesystem but not on Lambda, so this function raised
            // Runtime.ImportModuleError. It is the second state of the triage
            // state machine and that state has no Catch, so every triage
            // execution aborted before reaching acquisition.
            handler: 'src.acquisition.checkacquisition.lambda_handler',
            applicationName: 'checkAcquisition',
            functionName: 'Fo-checkAcquisition',
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
