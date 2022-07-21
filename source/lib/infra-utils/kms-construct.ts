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
import { IAspect, Lazy, RemovalPolicy } from 'aws-cdk-lib';
import {
    AccountRootPrincipal,
    ArnPrincipal,
    PolicyDocument,
    PolicyStatement,
} from 'aws-cdk-lib/aws-iam';
import { CfnKey, IKey, Key } from 'aws-cdk-lib/aws-kms';
import { CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { Construct, IConstruct } from 'constructs';

export interface KeyResolverProps {
    removalPolicy: RemovalPolicy;
    solutionName: string;
}

export interface KeyWithImportStatus {
    key: IKey;
    imported: boolean;
}

export class KeyResolverConstruct extends Construct {
    public kmsKeys: Record<string, KeyWithImportStatus>;
    public solutionName: string;

    constructor(scope: Construct, id: string, props: KeyResolverProps) {
        super(scope, id);

        this.solutionName = props.solutionName;
        this.kmsKeys = this.setupCMKs(props.removalPolicy, 'forensic');
    }

    private setupCMKs(removalPolicy: RemovalPolicy, keyPrefix: string) {
        const resolveKey = (name: string, arn: string) =>
            this.importCMK(name, arn) ?? this.createCMK(name, removalPolicy, keyPrefix);

        const customerManagedCMKArns = (<unknown>(
            this.node.tryGetContext('customerManagedCMKArns')
        )) as Record<string, string>;

        return {
            forensicsnsEncryptionKey: resolveKey(
                'forensicsnsEncryptionKey',
                customerManagedCMKArns?.forensicsnsEncryptionKey
            ),
            forensicLambdaEncryptionKey: resolveKey(
                'forensicLambdaEncryptionKey',
                customerManagedCMKArns?.forensicLambdaEncryptionKey
            ),
            forensicBucket: resolveKey(
                'forensicBucketEncryptionKey',
                customerManagedCMKArns?.forensicBucketEncryptionKey
            ),
            volumeEncryptionKey: resolveKey(
                'ebsVolumeKey',
                customerManagedCMKArns?.ebsVolumeKey
            ),
            forensicSQSEncryptionKey: resolveKey(
                'forensicSQSEncryptionKey',
                customerManagedCMKArns?.forensicSQSEncryptionKey
            ),
        };
    }

    private importCMK(name: string, arn?: string): KeyWithImportStatus | null {
        return arn
            ? {
                  key: Key.fromKeyArn(this, `CMKKey${name}`, arn),
                  imported: true,
              }
            : null;
    }

    private createCMK(
        name: string,
        removalPolicy: RemovalPolicy,
        keyPrefix: string
    ): KeyWithImportStatus {
        const solutionKey = new Key(this, `CMKKey${name}`, {
            description: `KMS Key for ${keyPrefix}/${name}`,
            alias: `${keyPrefix}-${name}`,
            enableKeyRotation: true,
            removalPolicy: removalPolicy,
        });
        return { key: solutionKey, imported: false };
    }
}

const ENCRYPT_ACTIONS = ['kms:Encrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*'];

const DECRYPT_ACTIONS = ['kms:Decrypt'];

const ADMIN_ACTIONS = [
    'kms:Create*',
    'kms:Describe*',
    'kms:Enable*',
    'kms:List*',
    'kms:Put*',
    'kms:Update*',
    'kms:Revoke*',
    'kms:Disable*',
    'kms:Get*',
    'kms:Delete*',
    'kms:TagResource',
    'kms:UntagResource',
    'kms:ScheduleKeyDeletion',
    'kms:CancelKeyDeletion',
];

export enum ResourceType {
    LAMBDA = 'Lambda',
    IAM = 'IAM',
}

interface Grants {
    [resource: string]: string[];
}

/*
 * Aspect to build a custom KMS CMK key policy.
 */
export class KmsCmkPolicyBuilder implements IAspect {
    public kmsKey: IKey;
    public encryptDecryptGrants: Grants = {};

    constructor(kmsKey: IKey) {
        this.kmsKey = kmsKey;
    }

    private generateCustomKeyPolicy(): PolicyDocument {
        return new PolicyDocument({
            statements: [
                new PolicyStatement({
                    sid: 'KeyAdministration',
                    actions: ADMIN_ACTIONS,
                    principals: [new AccountRootPrincipal()],
                    resources: ['*'],
                }),
                ...Object.keys(this.encryptDecryptGrants).map((resource) => {
                    return new PolicyStatement({
                        sid: `${resource}EncryptDecrypt`,
                        actions: [
                            ...ENCRYPT_ACTIONS,
                            ...DECRYPT_ACTIONS,
                            'kms:Describe*',
                        ],
                        principals: this.encryptDecryptGrants[resource].map(
                            (arnPrincipal) => new ArnPrincipal(arnPrincipal)
                        ),
                        resources: ['*'],
                    });
                }),
            ],
        });
    }

    public generateKeyPolicy() {
        const cfnKey = this.kmsKey?.node.defaultChild as CfnKey;
        cfnKey.keyPolicy = Lazy.any({
            produce: () => this.generateCustomKeyPolicy().toJSON(),
        });
    }

    /**
     * Grant encryption and decryption permissions to the given principal for the Aspects key
     * resourceType is used to group the principals together in the resultant key policy.
     * This method can be invoked from within
     */
    public grantEncryptDecrypt(principalArn: string, resourceType: ResourceType) {
        const resourceList = this.encryptDecryptGrants[resourceType] ?? [];

        resourceList.push(principalArn);

        this.encryptDecryptGrants[resourceType] = resourceList;
    }

    public visit(node: IConstruct): void {
        if (node instanceof CfnFunction) {
            this.grantEncryptDecrypt(node.role, ResourceType.LAMBDA);
        }
    }
}
