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

import { Duration } from 'aws-cdk-lib';
import { AnyPrincipal, Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { IKey, Key } from 'aws-cdk-lib/aws-kms';
import {
    BlockPublicAccess,
    Bucket,
    BucketEncryption,
    BucketProps,
    CfnBucket,
    StorageClass,
} from 'aws-cdk-lib/aws-s3';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export type AWSSecureBucketProps = Omit<
    BucketProps,
    | 'encryptionKey'
    | 'encryption'
    | 'blockPublicAccess'
    | 'accessControl'
    | 'versioned'
    | 'serverAccessLogsPrefix'
> & {
    encryptionKeyArn?: string;
    objectLockMode?: string;
    objectLockRetentionDays?: number;
};

/**
 * Awssecure bucket
 */
export class AWSSecureBucket extends Construct {
    public readonly bucket: Bucket;
    public readonly encryptionKey: IKey;

    constructor(scope: Construct, id: string, props?: AWSSecureBucketProps) {
        super(scope, id);

        this.encryptionKey = props?.encryptionKeyArn
            ? Key.fromKeyArn(this, `encryption-key-${id}`, props?.encryptionKeyArn)
            : new Key(this, `encryption-key-${id}`, {
                  removalPolicy: props?.removalPolicy,
                  enableKeyRotation: true,
              });

        this.bucket = new Bucket(this, `aws-${id}`, {
            ...props,
            encryptionKey: this.encryptionKey,
            encryption: BucketEncryption.KMS,
            blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
            enforceSSL: true,
            versioned: true,
            objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            autoDeleteObjects: false,
            serverAccessLogsPrefix: 'forensics',
            lifecycleRules: [
                {
                    abortIncompleteMultipartUploadAfter: Duration.days(300),
                    transitions: [
                        {
                            storageClass: StorageClass.INFREQUENT_ACCESS,
                            transitionAfter: Duration.days(30),
                        },
                        {
                            storageClass: StorageClass.INTELLIGENT_TIERING,
                            transitionAfter: Duration.days(60),
                        },
                        {
                            storageClass: StorageClass.GLACIER,
                            transitionAfter: Duration.days(180),
                        },
                        {
                            storageClass: StorageClass.DEEP_ARCHIVE,
                            transitionAfter: Duration.days(365),
                        },
                    ],
                },
            ],
        });

        if (props?.objectLockMode && props?.objectLockRetentionDays) {
            // Add Object Lock configuration to the bucket
            const bucket = this.bucket.node.defaultChild as CfnBucket;

            bucket.objectLockEnabled = true as boolean;
            bucket.objectLockConfiguration = {
                objectLockEnabled: 'Enabled',
                rule: {
                    defaultRetention: {
                        days: props.objectLockRetentionDays,
                        mode: props.objectLockMode,
                    },
                },
            } as s3.CfnBucket.ObjectLockConfigurationProperty;
        }

        this.bucket.addToResourcePolicy(
            new PolicyStatement({
                sid: 'HttpsOnly',
                resources: [`${this.bucket.bucketArn}/*`],
                actions: ['*'],
                principals: [new AnyPrincipal()],
                effect: Effect.DENY,
                conditions: {
                    Bool: {
                        'aws:SecureTransport': 'false',
                    },
                },
            })
        );
    }
}
