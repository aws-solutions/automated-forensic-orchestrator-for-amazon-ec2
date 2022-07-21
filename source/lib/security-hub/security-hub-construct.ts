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

import { Construct } from 'constructs';
import { Stack } from 'aws-cdk-lib';
import { ForensicsSecurityHubActionConstruct } from '../forensic-core/forensic-custom-action-construct';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { IRule, Rule, RuleTargetConfig } from 'aws-cdk-lib/aws-events';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';

export interface ForensicsSecurityHubConfigProps {
    subnetGroupName: string;
    vpc: IVpc;
    environment?: {
        [key: string]: string;
    };
}

/**
 * Forensics security hub action construct
 */
export class ForensicsSecurityHubConfigConstruct extends Construct {
    forensicSecHubDeadLetterQueue: Queue;

    constructor(scope: Construct, id: string, props: ForensicsSecurityHubConfigProps) {
        super(scope, id);
        //-------------------------------------------------------------------------
        // Custom Lambda Policy
        //
        this.forensicSecHubDeadLetterQueue = new Queue(
            this,
            'ForensicImageBuilderDeadLetterQueue',
            {
                encryption: QueueEncryption.KMS_MANAGED,
            }
        );

        const forensicCustomActionConstruct = new ForensicsSecurityHubActionConstruct(
            this,
            'securityHubCustomAction',
            {
                subnetGroupName: props.subnetGroupName,
                vpc: props.vpc,
                forensicDeadLetterQueue: this.forensicSecHubDeadLetterQueue,
            }
        );

        const customActionARN = `arn:aws:securityhub:${Stack.of(this).region}:${
            Stack.of(this).account
        }:action/custom/ForensicTriageAction`;

        const customIsolationActionARN = `arn:aws:securityhub:${Stack.of(this).region}:${
            Stack.of(this).account
        }:action/custom/ForensicIsolateAct`;
        const forensicAccount =
            this.node.tryGetContext('forensicAccount') || Stack.of(this).account;

        const forensicRegion =
            this.node.tryGetContext('forensicRegion') || Stack.of(this).region;

        if (forensicAccount != Stack.of(this).account) {
            const targetAccountBus = `arn:aws:events:${forensicRegion}:${forensicAccount}:event-bus/default`;
            const publishingRole = new Role(this, 'PublishingRole', {
                assumedBy: new ServicePrincipal('events.amazonaws.com'),
            });

            publishingRole.addToPolicy(
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    resources: [targetAccountBus],
                    actions: ['events:PutEvents'],
                })
            );

            const forensicRule = new Rule(this, `ForensicDefaultProcessorRule`, {
                eventPattern: {
                    source: [`aws.securityhub`],
                    detailType: [`Security Hub Findings - Custom Action`],
                    resources: [customActionARN],
                },
            });

            forensicRule.addTarget(this.bindRule(targetAccountBus, publishingRole));

            const forensicIsolationRule = new Rule(
                this,
                `ForensicDefaultIsolationProcessorRule`,
                {
                    eventPattern: {
                        source: [`aws.securityhub`],
                        detailType: [`Security Hub Findings - Custom Action`],
                        resources: [customIsolationActionARN],
                    },
                }
            );

            forensicIsolationRule.addTarget(
                this.bindRule(targetAccountBus, publishingRole)
            );

            forensicRule.node.addDependency(forensicCustomActionConstruct);
            forensicIsolationRule.node.addDependency(forensicCustomActionConstruct);
        }
    }

    private bindRule(targetAccountBus: string, publishingRole: Role) {
        return {
            bind(_rule: IRule): RuleTargetConfig {
                return {
                    arn: targetAccountBus,
                    role: publishingRole,
                };
            },
        };
    }
}
