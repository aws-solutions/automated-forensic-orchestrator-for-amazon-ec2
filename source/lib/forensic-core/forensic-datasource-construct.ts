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

import { Annotations, CfnOutput, RemovalPolicy } from 'aws-cdk-lib';
import {
    AttributeType,
    BillingMode,
    StreamViewType,
    Table,
    TableEncryption,
} from 'aws-cdk-lib/aws-dynamodb';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { ITopic, Topic } from 'aws-cdk-lib/aws-sns';
import { EmailSubscription } from 'aws-cdk-lib/aws-sns-subscriptions';
import { Construct } from 'constructs';
import { addCFNNagSuppressionTableName } from '../infra-utils/cfn-nag-suppression';

export interface AutConfigConstructProps {
    pointInTimeRecovery: boolean;
    notificationTopicEncryptionKey: IKey;
}

export class ForensicDataSourceConstruct extends Construct {
    public readonly forensicInstanceTable: Table;

    public readonly notificationTopic: ITopic;

    constructor(scope: Construct, id: string, props: AutConfigConstructProps) {
        super(scope, id);

        this.forensicInstanceTable = new Table(this, 'ForensicTable', {
            billingMode: BillingMode.PAY_PER_REQUEST,
            encryption: TableEncryption.AWS_MANAGED,
            tableName: 'ForensicTable',
            stream: StreamViewType.NEW_AND_OLD_IMAGES,
            partitionKey: { name: 'PK', type: AttributeType.STRING },
            sortKey: { name: 'SK', type: AttributeType.STRING },
            pointInTimeRecovery: props.pointInTimeRecovery,
            removalPolicy: RemovalPolicy.DESTROY,
        });

        addCFNNagSuppressionTableName(this.forensicInstanceTable);

        this.forensicInstanceTable.addGlobalSecondaryIndex({
            indexName: 'GSI1',
            partitionKey: { name: 'GSI1PK', type: AttributeType.STRING },
            sortKey: { name: 'GSI1SK', type: AttributeType.STRING },
        });

        this.notificationTopic = new Topic(this, 'ForensicNotificationTopic', {
            masterKey: props.notificationTopicEncryptionKey,
        });

        this.subscribeToTopic();

        const cfnSNSOutput = new CfnOutput(this, 'ForensicNotificationTopicARN', {
            value: this.notificationTopic.topicArn,
        });

        cfnSNSOutput.node.addDependency(this.notificationTopic);
    }

    private subscribeToTopic() {
        const emails = this.node.tryGetContext('forensicNotificationTargetEmails');
        if (emails) {
            if (!Array.isArray(emails)) {
                Annotations.of(this).addWarning(
                    'failureNotificationTargetEmails contains invalid value it should be a list of emails, skip subscription'
                );
            } else {
                (<Array<string>>emails).forEach((email) =>
                    this.notificationTopic.addSubscription(new EmailSubscription(email))
                );
            }
        }
    }
}
