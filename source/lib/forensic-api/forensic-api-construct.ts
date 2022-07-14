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
import { ITable } from 'aws-cdk-lib/aws-dynamodb';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import { CfnWebACLAssociation } from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import {
    AuthorizationConfig,
    AuthorizationType,
    AWSAppSyncApiConstruct,
    FieldLogLevel,
} from '../infra-utils/aws-appsync-api';
import {
    DynamoDbDataSourceConstruct,
    LambdaDataSourceConstruct,
    NoneDataSource,
    ResolverProps,
} from '../infra-utils/aws-appsync-data-source';
import { PythonLambdaConstruct } from '../infra-utils/aws-python-lambda-construct';
import { AWSWafWebACL, WAFScope } from '../infra-utils/aws-waf-web-acl';

export interface AwsForensicsApiConstructProps {
    readonly forensicDeadLetterQueue: IQueue;
    readonly forensicBucket: IBucket;
    readonly forensicBucketKey: IKey;
    readonly forensicTable: ITable;
    readonly vpc: IVpc;
    readonly apiAuthorizationConfig?: AuthorizationConfig;
    readonly wafAllowList?: string[];
    readonly wafRateLimit?: number;
}

/**
 * Forensics solutions Image builder constructs stack
 */
export class ForensicApiConstruct extends Construct {
    public readonly api: AWSAppSyncApiConstruct;
    public readonly forensicsPresignerFunction: IFunction;

    constructor(scope: Construct, id: string, props: AwsForensicsApiConstructProps) {
        super(scope, id);

        const wafWebAcl = new AWSWafWebACL(this, 'ForensicsApiWafWebACL', {
            name: 'ForensicApiWafWebACL',
            wafScope: WAFScope.REGIONAL,
            sampleRequestsEnabled: false,
            rateLimit: props.wafRateLimit ?? 1000,
            enableManagedRules: true,
            enableGqlCustomRules: true,
            allowList: props.wafAllowList ?? [],
        });

        this.api = new AWSAppSyncApiConstruct(this, 'ForensicsApi', {
            name: 'ForensicsApi',
            authorizationConfig: props.apiAuthorizationConfig ?? {
                defaultAuthorization: {
                    authorizationType: AuthorizationType.IAM,
                },
            },
            logConfig: {
                fieldLogLevel: FieldLogLevel.ALL,
            },
        });

        const cfnWebACLAssociation = new CfnWebACLAssociation(
            this,
            'ForensicsApiWafAssociation',
            {
                resourceArn: this.api.arn,
                webAclArn: wafWebAcl.webAcl.attrArn,
            }
        );

        cfnWebACLAssociation.node.addDependency(this.api);

        // API Data Sources
        const dynamoDataSource = new DynamoDbDataSourceConstruct(
            this,
            'ForensicsTableDataSource',
            {
                apiId: this.api.apiId,
                description: 'Forensics Data',
                tableName: props.forensicTable.tableName,
                tableRegion: Stack.of(this).region,
                readOnlyAccess: true,
            }
        );

        const presignerPolicies = [
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['s3:GetObject'],
                resources: [props.forensicBucket.arnForObjects('*')],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['dynamodb:GetItem'],
                resources: [props.forensicTable.tableArn],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: ['kms:DescribeKey', 'kms:Decrypt'],
                resources: [props.forensicBucketKey.keyArn],
            }),
        ];

        this.forensicsPresignerFunction = new PythonLambdaConstruct(
            this,
            'forensicsPresigner',
            {
                handler: 'src.presign.app.handler',
                applicationName: 'createPresignedUrl',
                functionName: 'Fo-createPresignedUrl',
                environment: {
                    INSTANCE_TABLE_NAME: props.forensicTable.tableName,
                    ARTIFACT_BUCKET_NAME: props.forensicBucket.bucketName,
                },
                initialPolicy: [...presignerPolicies],
                vpc: props.vpc,
                deadLetterQueue: props.forensicDeadLetterQueue,
            }
        ).function;

        const lambdaPresigner = new LambdaDataSourceConstruct(
            this,
            'ForensicsLambdaPresigner',
            {
                apiId: this.api.apiId,
                description: 'Forensics Presign URL Lambda Function',
                lambdaFunction: this.forensicsPresignerFunction,
            }
        );

        const notifySubscribers = new NoneDataSource(
            this,
            'NotifySubscribersDataSource',
            {
                apiId: this.api.apiId,
                description:
                    'Forensics Data Source for notifying subscribers of updates to Forensic Records',
            }
        );

        this.api.addSchemaDependency(dynamoDataSource.ds);
        this.api.addSchemaDependency(lambdaPresigner.ds);
        this.api.addSchemaDependency(notifySubscribers.ds);

        // Attach resolvers to API Data Sources
        [
            {
                typeName: 'Query',
                fieldName: 'allForensicRecords',
                requestMappingTemplateName: 'all-forensic-records-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'artifactsForRecord',
                requestMappingTemplateName: 'artifacts-for-record-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'timelineEventsForRecord',
                requestMappingTemplateName: 'timeline-events-for-record-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'getForensicRecord',
                requestMappingTemplateName: 'get-forensic-record-request',
                responseMappingTemplateName: 'single-item-response',
            },
            {
                typeName: 'Query',
                fieldName: 'listForensicRecordsForAccount',
                requestMappingTemplateName: 'list-forensic-records-for-account-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'listForensicRecordsForRegion',
                requestMappingTemplateName: 'list-forensic-records-for-region-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'listForensicRecordsForResource',
                requestMappingTemplateName: 'list-forensic-records-for-resource-request',
                responseMappingTemplateName: 'list-response',
            },
            {
                typeName: 'Query',
                fieldName: 'listForensicRecordsForResourceType',
                requestMappingTemplateName:
                    'list-forensic-records-for-resource-type-request',
                responseMappingTemplateName: 'list-response',
            },
        ].forEach((r: ResolverProps) => {
            dynamoDataSource.createResolver(r);
        });

        [
            {
                typeName: 'Query',
                fieldName: 'getArtifactDownloadUrl',
                requestMappingTemplateName: 'get-artifact-download-url-request',
                responseMappingTemplateName: 'single-item-response',
            },
        ].forEach((r: ResolverProps) => {
            lambdaPresigner.createResolver(r);
        });

        [
            {
                typeName: 'Mutation',
                fieldName: 'notifyForensicsRecordChange',
                requestMappingTemplateName: 'notify-request',
                responseMappingTemplateName: 'notify-response',
            },
            {
                typeName: 'Mutation',
                fieldName: 'notifyNewForensicTimelineEvent',
                requestMappingTemplateName: 'notify-request',
                responseMappingTemplateName: 'notify-response',
            },
            {
                typeName: 'Mutation',
                fieldName: 'notifyNewOrUpdatedForensicArtifact',
                requestMappingTemplateName: 'notify-request',
                responseMappingTemplateName: 'notify-response',
            },
        ].forEach((r: ResolverProps) => {
            notifySubscribers.createResolver(r);
        });
    }
}
