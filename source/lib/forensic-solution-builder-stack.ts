/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 *  with the License. A copy of the License is located at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

import { Construct } from 'constructs';
import {
    aws_events as events,
    Annotations,
    Aspects,
    CfnOutput,
    RemovalPolicy,
    Stack,
    StackProps,
} from 'aws-cdk-lib';
import { ForensicsAcquisitionConstruct } from './forensic-core/acquisition-functions-construct';
import { ForensicsCore } from './forensic-core/core-functions-construct';
import { ForensicDataSourceConstruct } from './forensic-core/forensic-datasource-construct';
import { ForensicsInvestigationConstruct } from './forensic-core/investigation-functions-construct';
import { InvestigationStepConstruct } from './forensic-orchestrator/investigation/investigation-step-functions';
import { TriageOrchestratorConstruct } from './forensic-orchestrator/triage/triage-step-functions';
import { AWSBaseInfraConstruct, BaseInfraProps } from './infra-utils/aws-baseinfra-stack';
import {
    KeyResolverConstruct,
    KeyWithImportStatus,
    KmsCmkPolicyBuilder,
    ResourceType,
} from './infra-utils/kms-construct';
import { AWSEventRuleConstruct } from './infra-utils/aws-event-rule-stack';
import { ForensicSSMDBuilderConstruct } from './forensic-ssm-document-builder-stack';
import { AWSSecureBucket } from './infra-utils/aws-secure-bucket';
import { IVpc, Vpc } from 'aws-cdk-lib/aws-ec2';
import { Bucket, IBucket } from 'aws-cdk-lib/aws-s3';

import { ParameterTier, StringParameter } from 'aws-cdk-lib/aws-ssm';
import {
    AccountRootPrincipal,
    CfnInstanceProfile,
    Effect,
    IRole,
    ManagedPolicy,
    PolicyStatement,
    Role,
    ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { ILogGroup, LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Dashboard, PeriodOverride } from 'aws-cdk-lib/aws-cloudwatch';
import { StepFunctionDashboardConstruct } from './infra-utils/aws-dashboard-construct';
import { AuthorizationConfig } from './infra-utils/aws-appsync-api';
import { ForensicApiConstruct } from './forensic-api/forensic-api-construct';
import { IKey, Key } from 'aws-cdk-lib/aws-kms';
import {
    APPLICATION_ACCOUNTS,
    APP_ACCOUNT_FORENSIC_KMS_KEY_ALIAS,
    DISK_SIZE,
    DISK_SIZE_CONFIG,
    FORENSIC_IMAGE_NAME_CONFIG,
    IS_SAND_BOX,
    RETAIN_DATA,
    SECURITYHUB_ACCOUNT,
    SUBNET_GROUP_CONFIG,
    VOL2_PROFILES_BUCKET,
    VOLATILITY2_PROFILES_PREFIX,
    VPC_CONFIG_DETAILS,
    VPC_INFO_CONFIG,
} from './infra-utils/infra-types';
import { Trail } from 'aws-cdk-lib/aws-cloudtrail';
import {
    AWSCloudTrailDataEventTrail,
    CloudTrailDataEventSelector,
} from './infra-utils/aws-cloudtrial-trail';
import { SolutionMetricsCollectorConstruct } from './infra-utils/solution-metrics-collector';
import { SOLUTION_ID, SOLUTION_VERSION } from './infra-utils/aws-solution-environment';
import { Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { accessLogsBucketCfnNagSuppression } from './infra-utils/cfn-nag-suppression';
import { ForensicsSecurityHubConfigConstruct } from './security-hub/security-hub-construct';

export interface AwsForensicsSolutionStackProps extends StackProps {
    readonly description: string;
    readonly solutionId: string;
    readonly solutionTradeMarkName: string;
    readonly solutionProvider: string;
    readonly solutionBucket: string;
    readonly solutionName: string;
    readonly solutionVersion: string;
    readonly stackPrefix: string;
    readonly forensicBucketRetentionDays?: number;
    readonly forensicBucketComplianceMode?: boolean;
    readonly forensicBucketAccessIamRoleNames?: string[];
    readonly deployForensicApi?: boolean;
    readonly apiNotifications?: boolean;
    readonly apiAuthorizationConfig?: AuthorizationConfig;
    readonly wafAllowList?: string[];
    readonly wafRateLimit?: number;
}

/**
 * Forensics solutions constructs stack
 */
export class ForensicsSolutionsConstructsStack extends Stack {
    public vpc: IVpc;
    public forensicBucket: IBucket;

    public forensicBucketKey: IKey;

    public forensicCloudTrail: Trail;

    private forensicApi?: ForensicApiConstruct;

    private removalPolicy: RemovalPolicy;

    private s3CopyRole: IRole;

    private forensicLogGroup: ILogGroup;

    private dashboard: Dashboard;

    private kmsKeys: Record<string, KeyWithImportStatus>;

    public lambdaEnvironmentProps: {
        [key: string]: string;
    };
    public readonly AMIIdLocation: StringParameter;
    importedVPC: boolean;
    forensicDeadLetterQueue: Queue;

    constructor(scope: Construct, id: string, props?: AwsForensicsSolutionStackProps) {
        super(scope, id, props);
        const forensicLogEncryptionKey = new Key(this, 'forensicLogGroupKey', {
            removalPolicy: RemovalPolicy.DESTROY,
            enableKeyRotation: true,
        });

        forensicLogEncryptionKey.addToResourcePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                sid: 'Allow forensic Logs to use the key',
                principals: [
                    new ServicePrincipal(`logs.${Stack.of(this).region}.amazonaws.com`),
                ],
                actions: [
                    'kms:ReEncrypt',
                    'kms:GenerateDataKey',
                    'kms:Encrypt',
                    'kms:DescribeKey',
                    'kms:Decrypt',
                ],
                // This is a resource policy, can only reference  and specifying encryptionKey would start a Circular dependency
                resources: ['*'],
            })
        );
        // remove policy specified in json for the given configuration
        this.forensicLogGroup = new LogGroup(this, 'forensicLogGroup', {
            retention: RetentionDays.TEN_YEARS,
            encryptionKey: forensicLogEncryptionKey,
        });

        this.removalPolicy = this.node.tryGetContext(RETAIN_DATA)
            ? RemovalPolicy.RETAIN
            : RemovalPolicy.DESTROY;

        this.kmsKeys = new KeyResolverConstruct(this, 'KeyResolverConstruct', {
            removalPolicy: this.removalPolicy,
            solutionName: props?.solutionName ?? 'forensicSolution',
        }).kmsKeys;

        const appAccountKMSKey = this.node.tryGetContext(
            APP_ACCOUNT_FORENSIC_KMS_KEY_ALIAS
        );

        this.forensicCloudTrail = new AWSCloudTrailDataEventTrail(
            this,
            'forensicCloudTrail'
        ).trail;

        this.dashboard = new Dashboard(
            this,
            'ForensicDashboard',
            /* all optional props */ {
                dashboardName: `Forensic_Dashboard_${Stack.of(this).region}`,
                end: 'end',
                periodOverride: PeriodOverride.AUTO,
                start: 'start',
            }
        );

        const accessLogsBucket = new Bucket(this, 'AccessLogsBucket');

        accessLogsBucketCfnNagSuppression(accessLogsBucket);

        /**
         * S3 Bucket
         * Hosts the Forensic reports to eb shared.
         */
        const secureBucket = new AWSSecureBucket(this, 'forensicBucket', {
            encryptionKeyArn: this.kmsKeys.forensicBucket.key.keyArn,
            objectLockMode: props?.forensicBucketComplianceMode
                ? 'COMPLIANCE'
                : 'GOVERNANCE',
            objectLockRetentionDays: props?.forensicBucketRetentionDays,
            serverAccessLogsBucket: accessLogsBucket,
        });
        this.forensicBucket = secureBucket.bucket;
        this.forensicBucketKey = secureBucket.encryptionKey;

        //creates a role for S3 Copy role
        this.s3CopyRole = new Role(this, `s3CopyRole`, {
            assumedBy: new AccountRootPrincipal(),
            path: '/',
        });

        const vol2ProfilesBucket =
            this.node.tryGetContext(VOL2_PROFILES_BUCKET) ||
            `${this.forensicBucket.bucketName}`;

        const vol2ProfilesPrefix =
            this.node.tryGetContext(VOLATILITY2_PROFILES_PREFIX) ||
            'volatility2/profiles';

        const forensicSSMDBuilder = new ForensicSSMDBuilderConstruct(
            this,
            'ForensicSSMDBuilderStack',
            {}
        );
        this.lambdaEnvironmentProps = {
            ...forensicSSMDBuilder.lambdaEnvironmentProps,
        };

        let environmentProps: {
            [key: string]: string;
        };
        // eslint-disable-next-line prefer-const
        environmentProps = this.lambdaEnvironmentProps;
        //Create EnvironmentVariable for lambda

        this.lambdaEnvironmentProps = {
            ...environmentProps,
        };

        this.forensicBucket.grantWrite(this.s3CopyRole);
        this.forensicBucket.grantReadWrite(this.s3CopyRole);

        const vpcConfigDetails = this.node.tryGetContext(VPC_CONFIG_DETAILS);
        const forensicImageName = this.node.tryGetContext(FORENSIC_IMAGE_NAME_CONFIG);

        if (!forensicImageName) {
            Annotations.of(this).addError('configuration forensicImageName is mandatory');
        }
        //Sets the SSM Parameter to n/a - this will be updated by forensic image builder stack post image creation
        const ec2ForensicImage = this.node.tryGetContext('ec2ForensicImage') || 'n/a';

        //Loads the Forensic AMI details in SSM parameter for creating Investigation instance
        this.AMIIdLocation = new StringParameter(this, 'Parameter', {
            description: `The value of image ${forensicImageName}`,
            parameterName: `${forensicImageName}`,
            stringValue: ec2ForensicImage,
            tier: ParameterTier.ADVANCED,
        });
        //Image details are shared in CFN output
        new CfnOutput(this, 'AMIIdLocation', {
            value: this.AMIIdLocation.parameterName,
        });
        const subnetGroupName = this.node.tryGetContext(SUBNET_GROUP_CONFIG) || 'service';
        this.importedVPC = false;
        if (
            vpcConfigDetails &&
            (vpcConfigDetails.isExistingVPC as boolean) &&
            vpcConfigDetails.vpcID
        ) {
            const vpcID = vpcConfigDetails.vpcID;

            this.vpc = Vpc.fromLookup(this, 'vpc', {
                vpcId: vpcID,
            });
            this.importedVPC = true;
        } else {
            const vpcInfo = this.node.tryGetContext(VPC_INFO_CONFIG);
            const baseinfra = new AWSBaseInfraConstruct(
                this,
                'forensicInfra',
                vpcInfo as BaseInfraProps
            );
            this.vpc = baseinfra.vpc;
        }
        if (this.node.tryGetContext(IS_SAND_BOX) == true) {
            new ForensicsSecurityHubConfigConstruct(
                this,
                'ForensicSecurityHubConstruct',
                {
                    subnetGroupName: subnetGroupName,
                    vpc: this.vpc,
                }
            );
        }
        const forensicDataSource = new ForensicDataSourceConstruct(
            this,
            'forensicsDataSource',
            {
                pointInTimeRecovery: true,
                notificationTopicEncryptionKey: this.kmsKeys.forensicsnsEncryptionKey.key,
            }
        );
        const applicationAccounts = this.node.tryGetContext(APPLICATION_ACCOUNTS);

        const diskSize = this.isNumber(this.node.tryGetContext(DISK_SIZE_CONFIG))
            ? this.node.tryGetContext(DISK_SIZE_CONFIG)
            : DISK_SIZE;

        this.forensicDeadLetterQueue = new Queue(this, 'ForensicDeadLetterQueue', {
            encryption: QueueEncryption.KMS,
            encryptionMasterKey: this.kmsKeys.forensicSQSEncryptionKey.key,
        });
        /**
         * Appsync GraphQL API
         * Provides an API that allows querying of the forensic record database
         */
        this.createAPI(props, forensicDataSource);

        const forensicsCoreFunctions = new ForensicsCore(this, 'ForensicsCore', {
            forensicDeadLetterQueue: this.forensicDeadLetterQueue,
            subnetGroupName: subnetGroupName,
            vpc: this.vpc,
            instanceTable: forensicDataSource.forensicInstanceTable,
            applicationAccounts: applicationAccounts,
            dashboard: this.dashboard,
            notificationTopic: forensicDataSource.notificationTopic,
            notificationTopicEncryptionKey: this.kmsKeys.forensicsnsEncryptionKey.key,
            environment: {
                FORENSIC_BUCKET: this.forensicBucket.bucketName,
            },
            ...(this.forensicApi && {
                environment: {
                    FORENSIC_BUCKET: this.forensicBucket.bucketName,
                    APPSYNC_API_ENDPOINT: this.forensicApi.api.graphqlUrl,
                    ...(props?.apiNotifications && {
                        APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS: 'ENABLED',
                    }),
                },
                forensicApiResources: [
                    'notifyForensicsRecordChange',
                    'notifyNewForensicTimelineEvent',
                    'notifyNewOrUpdatedForensicArtifact',
                ].map((field) => {
                    return `${this.forensicApi?.api.arn}/types/Mutation/fields/${field}`;
                }),
            }),
        });
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsCoreFunctions.triageLambda
        );

        this.validateApplicationAccountConfig(applicationAccounts);

        //creates a role for ImageBuilder to build EC2 image
        const investigationInstanceRole = new Role(this, `InvestigationInstanceRole`, {
            assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
            path: '/executionServiceEC2Role/',
        });

        //creates a the necessary policy for ImageBuilder to build EC2 image
        investigationInstanceRole.addToPolicy(
            new PolicyStatement({
                resources: [this.forensicBucket.bucketArn],
                actions: ['s3:PutObject', 's3:Get*', 's3:List*'],
            })
        );

        this.forensicBucket.grantRead(investigationInstanceRole);
        this.forensicBucket.grantReadWrite(investigationInstanceRole);

        //Adds SSM  Managed policy to role
        investigationInstanceRole.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')
        );
        //Adds EC2InstanceProfileForImageBuilder policy to role
        investigationInstanceRole.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('EC2InstanceProfileForImageBuilder')
        );

        //Builds the instance Profile to be attached to EC2 instance created during image building
        const investigationInstanceProfile = new CfnInstanceProfile(
            this,
            `investigationInstanceProfile`,
            {
                roles: [investigationInstanceRole.roleName],
                instanceProfileName: `ForensicInstanceProfile-${Stack.of(this).region}`,
            }
        );

        const forensicsAcquisitionFns = new ForensicsAcquisitionConstruct(
            this,
            'forensicsDiskAcquisition',
            {
                forensicDeadLetterQueue: this.forensicDeadLetterQueue,
                subnetGroupName: subnetGroupName,
                vpc: this.vpc,
                instanceTable: forensicDataSource.forensicInstanceTable,
                environment: {
                    ...this.lambdaEnvironmentProps,
                    ...{ S3_BUCKET_KEY_ARN: this.forensicBucketKey.keyArn },
                    FORENSIC_EBS_KEY_ID: this.kmsKeys.volumeEncryptionKey?.key.keyArn,
                },
                forensicBucket: this.forensicBucket,
                instanceProfileARN: investigationInstanceProfile.attrArn!,
                s3CopyRole: this.s3CopyRole,
                applicationAccounts: applicationAccounts,
                dashboard: this.dashboard,
                ...(this.forensicApi && {
                    forensicApiResources: [
                        'notifyForensicsRecordChange',
                        'notifyNewForensicTimelineEvent',
                        'notifyNewOrUpdatedForensicArtifact',
                    ].map((field) => {
                        return `${this.forensicApi?.api.arn}/types/Mutation/fields/${field}`;
                    }),
                }),
                appAccountKMSKeyAlias: appAccountKMSKey,
            }
        );

        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsCoreFunctions.triageLambda
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsAcquisitionFns.performInstanceSnapShotLambda
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsAcquisitionFns.checkMemoryAcquisitionCompletionLambda
        );

        const forensicsInvestigationFns = new ForensicsInvestigationConstruct(
            this,
            'forensicsInvestigationFns',
            {
                forensicDeadLetterQueue: this.forensicDeadLetterQueue,
                subnetGroupName: subnetGroupName,
                vpc: this.vpc,
                instanceTable: forensicDataSource.forensicInstanceTable,
                environment: {
                    ...this.lambdaEnvironmentProps,
                    ...{ S3_BUCKET_KEY_ARN: this.forensicBucketKey.keyArn },
                    INSTANCE_TABLE_NAME:
                        forensicDataSource.forensicInstanceTable.tableName,
                    VOLATILITY2_PROFILES_BUCKET: vol2ProfilesBucket,
                    VOLATILITY2_PROFILES_PREFIX: vol2ProfilesPrefix,
                    DISK_SIZE: diskSize,
                },
                forensicBucket: this.forensicBucket,
                s3CopyRole: this.s3CopyRole,
                instanceProfileARN: investigationInstanceProfile.attrArn!,
                instanceProfileRole: investigationInstanceRole,
                dashboard: this.dashboard,
                forensicImageName: forensicImageName,
                ...(this.forensicApi && {
                    forensicApiResources: [
                        'notifyForensicsRecordChange',
                        'notifyNewForensicTimelineEvent',
                        'notifyNewOrUpdatedForensicArtifact',
                    ].map((field) => {
                        return `${this.forensicApi?.api.arn}/types/Mutation/fields/${field}`;
                    }),
                }),
                ebsEncryptionKeyID: this.kmsKeys.volumeEncryptionKey.key.keyArn,
            }
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsInvestigationFns.createForensicInstanceLambda
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsInvestigationFns.checkInstanceStatusLambda
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsInvestigationFns.attachEBSSnapShotLambda
        );

        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsInvestigationFns.runMemoryAnalysisLambda
        );
        forensicDataSource.forensicInstanceTable.grantReadWriteData(
            forensicsInvestigationFns.checkForensicInvestigationStatusLambda
        );

        forensicsInvestigationFns.node.addDependency(forensicSSMDBuilder);

        //CMK Key support
        const kmsStatement = new PolicyStatement({
            effect: Effect.ALLOW,
            actions: [
                'kms:Describe*',
                'kms:EnableKey',
                'kms:Get*',
                'kms:GenerateDataKey*',
                'kms:Encrypt',
                'kms:Decrypt',
                'kms:ReEncrypt*',
            ],
            resources: [this.kmsKeys.volumeEncryptionKey?.key.keyArn],
        });

        //kms grant is provided to * to support encrypted AWS Managed keys ebs volumes
        const kmsGrantStatement = new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['kms:CreateGrant'],
            resources: ['*'],
            conditions: {
                Bool: {
                    'kms:GrantIsForAWSResource': true,
                },
            },
        });

        forensicsInvestigationFns.createForensicInstanceLambda.addToRolePolicy(
            kmsGrantStatement
        );
        forensicsInvestigationFns.attachEBSSnapShotLambda.addToRolePolicy(
            kmsGrantStatement
        );
        forensicsAcquisitionFns.performSnapshotCopyLambda.addToRolePolicy(
            kmsGrantStatement
        );
        investigationInstanceRole.addToPolicy(kmsGrantStatement);

        forensicsInvestigationFns.createForensicInstanceLambda.addToRolePolicy(
            kmsStatement
        );
        forensicsInvestigationFns.attachEBSSnapShotLambda.addToRolePolicy(kmsStatement);
        forensicsAcquisitionFns.performSnapshotCopyLambda.addToRolePolicy(kmsStatement);
        investigationInstanceRole.addToPolicy(kmsStatement);

        const investigationStepConstruct = new InvestigationStepConstruct(
            this,
            'InvestigationStepConstruct',
            {
                createForensicInstanceLambda:
                    forensicsInvestigationFns.createForensicInstanceLambda,
                checkInstanceStatusLambda:
                    forensicsInvestigationFns.checkInstanceStatusLambda,
                attachEBSSnapShotLambda:
                    forensicsInvestigationFns.attachEBSSnapShotLambda,
                runMemoryAnalysisLambda:
                    forensicsInvestigationFns.runMemoryAnalysisLambda,
                runForensicsCommandLambda:
                    forensicsInvestigationFns.runForensicsCommandLambda,
                checkForensicInvestigationStatusLambda:
                    forensicsInvestigationFns.checkForensicInvestigationStatusLambda,
                sendNotificationLambda: forensicsCoreFunctions.sendNotificationLambda,
                sendErrorNotificationLambda:
                    forensicsCoreFunctions.sendErrorNotificationLambda,
                terminateForensicInstanceLambda:
                    forensicsInvestigationFns.terminateForensicInstanceLambda,
                investigationLogGroup: this.forensicLogGroup,
            }
        );

        investigationStepConstruct.node.addDependency(forensicSSMDBuilder);

        const investigationSFDashboard = new StepFunctionDashboardConstruct(
            this,
            'InvestigationSFnsDashboard',
            {
                dashboard: this.dashboard,
                stateMachine: investigationStepConstruct.getStateMachine(),
                applicationName: 'Forensic Investigation',
            }
        );

        investigationSFDashboard.node.addDependency(
            investigationStepConstruct.getStateMachine()
        );

        const triageConstruct = new TriageOrchestratorConstruct(
            this,
            'TriageOrchestratorConstruct',
            {
                vpcId: this.vpc.vpcId,
                forensicsAcquisitionFns: forensicsAcquisitionFns,
                investigationSM: investigationStepConstruct.getStateMachine(),
                triageInstanceLambda: forensicsCoreFunctions.triageLambda,
                snsTopic: forensicDataSource.notificationTopic,
                snsDataKey: this.kmsKeys.forensicsnsEncryptionKey.key,
                triageLogGroup: this.forensicLogGroup,
                instanceIsolationLambda: forensicsCoreFunctions.isolationLambda,
                sendNotificationLambda: forensicsCoreFunctions.sendNotificationLambda,
                sendErrorNotificationLambda:
                    forensicsCoreFunctions.sendErrorNotificationLambda,
                forensicTable: forensicDataSource.forensicInstanceTable,
            }
        );

        const triageSFDashboard = new StepFunctionDashboardConstruct(
            this,
            'TriageSFnsDashboard',
            {
                dashboard: this.dashboard,
                stateMachine: triageConstruct.triageStepfunction,
                applicationName: 'Forensic Triaging',
            }
        );
        triageSFDashboard.node.addDependency(triageConstruct.triageStepfunction);

        const memoryAcquisitionSFDashboard = new StepFunctionDashboardConstruct(
            this,
            'MemoryAcquisitionSFnsDashboard',
            {
                dashboard: this.dashboard,
                stateMachine: triageConstruct.memoryAcquisitionStepfunction,
                applicationName: 'Forensic Memory Acquisition',
            }
        );
        memoryAcquisitionSFDashboard.node.addDependency(
            triageConstruct.memoryAcquisitionStepfunction
        );

        const diskAcquisitionSFDashboard = new StepFunctionDashboardConstruct(
            this,
            'DiskAcquisitionSFnsDashboard',
            {
                dashboard: this.dashboard,
                stateMachine: triageConstruct.diskAcquisitionStepfunction,
                applicationName: 'Forensic Disk Acquisition',
            }
        );
        diskAcquisitionSFDashboard.node.addDependency(
            triageConstruct.diskAcquisitionStepfunction
        );

        /**
         * Build Custom KMS Key Policy for the Forensics Bucket Key if it has not been imported
         */
        if (!this.kmsKeys.forensicBucket.imported) {
            const kmsCmkPolicyBuilder = new KmsCmkPolicyBuilder(
                this.kmsKeys.forensicBucket.key
            );

            props?.forensicBucketAccessIamRoleNames?.forEach((role) => {
                kmsCmkPolicyBuilder.grantEncryptDecrypt(
                    `arn:aws:iam::${this.account}:role/${role}`,
                    ResourceType.IAM
                );
            });

            kmsCmkPolicyBuilder.grantEncryptDecrypt(
                this.s3CopyRole.roleArn,
                ResourceType.IAM
            );
            kmsCmkPolicyBuilder.grantEncryptDecrypt(
                investigationInstanceRole.roleArn,
                ResourceType.IAM
            );

            Aspects.of(forensicsCoreFunctions).add(kmsCmkPolicyBuilder);
            Aspects.of(forensicsAcquisitionFns).add(kmsCmkPolicyBuilder);
            Aspects.of(forensicsInvestigationFns).add(kmsCmkPolicyBuilder);

            // Generate key policy after selecting principals
            kmsCmkPolicyBuilder.generateKeyPolicy();
        }

        /**
         * Add CloudTrail event selectors
         */
        const cloudTrailEventSelector = new CloudTrailDataEventSelector(
            this.forensicCloudTrail
        );

        Aspects.of(this).add(cloudTrailEventSelector);
        cloudTrailEventSelector.addEventSelectorsToTrail();

        const secHubAccount =
            this.node.tryGetContext(SECURITYHUB_ACCOUNT) || Stack.of(this).account;

        const customActionARN =
            // forensicCustomActionConstruct.customAction.getAttString('Arn') ||
            `arn:aws:securityhub:${props?.env?.region}:${secHubAccount}:action/custom/ForensicTriageAction`;

        const customIsolationActionARN = `arn:aws:securityhub:${props?.env?.region}:${secHubAccount}:action/custom/ForensicIsolateAct`;

        new events.CfnEventBusPolicy(this, 'secHubEventBusPolicy', {
            // the properties below are optional
            action: 'events:PutEvents',
            eventBusName: 'default',
            principal: secHubAccount,
            statementId: `AcceptFrom${secHubAccount}`,
        });

        const eventRuleNestedConstruct = new AWSEventRuleConstruct(
            this,
            'eventRuleNestedAction',
            {
                customActionARN: customActionARN,
                triageStepfunction: triageConstruct.triageStepfunction,
            }
        );

        const eventRuleIsolateConstruct = new AWSEventRuleConstruct(
            this,
            'eventRuleIsolateNestedAction',
            {
                customActionARN: customIsolationActionARN,
                triageStepfunction: triageConstruct.triageStepfunction,
            }
        );

        eventRuleNestedConstruct.node.addDependency(triageConstruct);
        eventRuleIsolateConstruct.node.addDependency(triageConstruct);
        eventRuleNestedConstruct.node.addDependency(triageConstruct);

        const vpcIDOutPut = new CfnOutput(this, 'vpcID', {
            value: this.vpc.vpcId,
        });
        vpcIDOutPut.node.addDependency(this.vpc);

        const sendAnonymousMetric = this.getConfigForMetrics();

        new SolutionMetricsCollectorConstruct(this, 'metrics-collector-construct', {
            version: SOLUTION_VERSION,
            solutionId: SOLUTION_ID,
            solutionDisplayName: 'AWS Compute Forensic Solution',
            sendAnonymousMetric: sendAnonymousMetric,
            metricsData: {
                enabledAPI: props?.deployForensicApi,
                importedVpc: this.importedVPC,
            },
        });
    }

    private getConfigForMetrics() {
        const sendAnonymousMetric =
            this.node.tryGetContext('sendAnonymousMetric') ?? 'Yes';
        if (sendAnonymousMetric && !['Yes', 'No'].includes(sendAnonymousMetric)) {
            Annotations.of(this).addError(
                'Configuration sendAnonymousMetric can only contain value Yes or No'
            );
        }
        return sendAnonymousMetric;
    }

    private createAPI(
        props: AwsForensicsSolutionStackProps | undefined,
        forensicDataSource: ForensicDataSourceConstruct
    ) {
        if (props?.deployForensicApi) {
            this.forensicApi = new ForensicApiConstruct(this, 'ForensicApi', {
                forensicDeadLetterQueue: this.forensicDeadLetterQueue,
                forensicBucket: this.forensicBucket,
                forensicBucketKey: this.forensicBucketKey,
                forensicTable: forensicDataSource.forensicInstanceTable,
                apiAuthorizationConfig: props.apiAuthorizationConfig,
                wafAllowList: props.wafAllowList,
                wafRateLimit: props.wafRateLimit,
                vpc: this.vpc,
            });

            this.forensicApi.node.addDependency(forensicDataSource.forensicInstanceTable);

            this.lambdaEnvironmentProps['APPSYNC_API_ENDPOINT'] =
                this.forensicApi.api.graphqlUrl;
        }

        if (props?.apiNotifications) {
            this.lambdaEnvironmentProps['APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS'] =
                'ENABLED';
        }
    }

    private validateApplicationAccountConfig(applicationAccounts: any) {
        if (applicationAccounts && !Array.isArray(applicationAccounts)) {
            Annotations.of(this).addError(
                'applicationAccounts must be a list of accounts'
            );
        }
    }

    private isNumber = (val: string | number) =>
        !!(val || val === 0) && !isNaN(Number(val.toString()));
}
