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

import { Trail, CfnTrail, DataResourceType } from 'aws-cdk-lib/aws-cloudtrail';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct, IConstruct } from 'constructs';
import { AWSSecureBucket } from './aws-secure-bucket';
import { IAspect, Stack } from 'aws-cdk-lib';
import { CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { CfnBucket } from 'aws-cdk-lib/aws-s3';

/**
 * CloudTrail Trail for Data Events
 */
export class AWSCloudTrailDataEventTrail extends Construct {
    public readonly trail: Trail;

    constructor(scope: Construct, id: string) {
        super(scope, id);

        /**
         * S3 Bucket to host forensic CLoudTrail
         */
        const trailBucket = new AWSSecureBucket(this, 'forensicTrailBucket');

        const trailName = 'forensicSolutionTrail';

        trailBucket.encryptionKey.addToResourcePolicy(
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                resources: ['*'],
                actions: ['kms:GenerateDataKey*'],
                principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
                conditions: {
                    StringLike: {
                        'kms:EncryptionContext:aws:cloudtrail:arn': [
                            `arn:aws:cloudtrail:*:${Stack.of(this).account}:trail/*`,
                        ],
                    },
                    StringEquals: {
                        'aws:SourceArn': `arn:aws:cloudtrail:${Stack.of(this).region}:${
                            Stack.of(this).account
                        }:trail/${trailName}`,
                    },
                },
            })
        );

        /**
         * CloudTrail Trail
         */
        this.trail = new Trail(this, 'ForensicSolutionCloudTrail', {
            trailName: trailName,
            bucket: trailBucket.bucket,
            encryptionKey: trailBucket.encryptionKey,
            enableFileValidation: true,
            sendToCloudWatchLogs: true,
            cloudWatchLogsRetention: logs.RetentionDays.ONE_YEAR,
            includeGlobalServiceEvents: false,
            isMultiRegionTrail: false,
        });
    }
}

/*
 * Aspect to select S3 objects and Lambda functions from the stack to create a data event CloudTrail Trail.
 */
export class CloudTrailDataEventSelector implements IAspect {
    private trail: Trail;
    private dataResources: CfnTrail.DataResourceProperty[];

    constructor(trail: Trail) {
        this.trail = trail;
        this.dataResources = [];
    }

    public visit(node: IConstruct): void {
        if (node instanceof CfnBucket) {
            this.dataResources.push({
                type: DataResourceType.S3_OBJECT,
                values: [`${node.attrArn}/`],
            });
        } else if (node instanceof CfnFunction) {
            this.dataResources.push({
                type: DataResourceType.LAMBDA_FUNCTION,
                values: [node.attrArn],
            });
        }
    }

    public addEventSelectorsToTrail(): void {
        const trail = this.trail.node.defaultChild;

        (trail as CfnTrail).eventSelectors = [
            {
                dataResources: this.dataResources,
                includeManagementEvents: false,
                readWriteType: 'All',
            },
        ] as CfnTrail.EventSelectorProperty[];
    }
}
