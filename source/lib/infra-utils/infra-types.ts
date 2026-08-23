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

export const environmentValues = {
    WAIT_STATE_TIME: 120,
};

export const SSM_DIRECTORY = 'ssmDocumentsDir';

export const VOL3_SYMBOLS_BUCKET = 'vol3SymbolsBucket';

export const DISK_SIZE = '512';

export const DISK_SIZE_CONFIG = 'diskSize';

/**
 * Instance types for the forensic analysis instance, tried in order.
 *
 * `m4.2xlarge` was hardcoded here, as a single type. The subnet - and therefore
 * the Availability Zone - is fixed, so that meant one AZ's capacity for one type
 * with no fallback, and it failed a real disk investigation twice with
 * InsufficientInstanceCapacity: once on the previous generation m4.2xlarge, then
 * again on m6i.2xlarge. Both times the snapshots had already been taken, so the
 * investigation was lost for a reason that had nothing to do with the case.
 *
 * Every type listed is 8 vCPU and 32 GiB, so they are interchangeable here.
 * `createForensicInstance` walks the list on capacity errors only; a malformed
 * request still fails immediately.
 *
 * Note that createForensicInstance's user data discovers the evidence volume
 * rather than assuming /dev/xvdf, because Nitro instance types enumerate EBS
 * volumes as NVMe devices.
 */
export const FORENSIC_INSTANCE_TYPE =
    'm6i.2xlarge,m6a.2xlarge,m5.2xlarge,m5a.2xlarge';

export const FORENSIC_INSTANCE_TYPE_CONFIG = 'forensicInstanceType';

/**
 * Memory acquisition tools to try, in order, until one produces a capture that
 * contains a kernel banner.
 *
 * A preference list rather than a single choice for the same reason
 * FORENSIC_INSTANCE_TYPE is: LiME intermittently returns a full size image whose
 * pages are almost entirely zero with no kernel banner - 3 of 9 acquisitions
 * observed - and AVML reads /dev/crash, /dev/mem or /proc/kcore rather than
 * loading a kernel module, so the two fail for unrelated reasons. Both write
 * LiME format, so the investigation side is unaffected by which one ran.
 *
 * The default keeps LiME first, which is the mechanism this solution has always
 * used. Setting this to 'avml,lime' would avoid loading a kernel module into a
 * possibly compromised host at all, which is the more conservative thing to do -
 * but the failure rates have not been compared yet, and one good AVML capture is
 * not evidence of a better rate. See the Unreleased section of the CHANGELOG.
 */
export const MEMORY_ACQUISITION_TOOLS = 'lime,avml';

export const MEMORY_ACQUISITION_TOOLS_CONFIG = 'memoryAcquisitionTools';

export const APPLICATION_ACCOUNTS = 'applicationAccounts';

export const SECURITYHUB_ACCOUNT = 'secHubAccount';

export const IMAGE_BUILDER_PIPELINE_CONFIG = 'imageBuilderPipelines';

export const FORENSIC_BUCKET_RETENTION_DAYS = 'forensicBucketRetentionDays';

export const FORENSIC_BUCKET_COMPLIANCE_MODE = 'forensicBucketComplianceMode';

export const FORENSIC_BUCKET_ACCESS_IAM_ROLES_NAMES = 'forensicBucketAccessIamRoleNames';

export const VPC_INFO_CONFIG = 'vpcInfo';

export const IS_SAND_BOX = 'sandbox';

export const SUBNET_GROUP_CONFIG = 'subnetGroupName';

export const FORENSIC_IMAGE_NAME_CONFIG = 'forensicImageName';

export const VPC_CONFIG_DETAILS = 'vpcConfigDetails';

export const RETAIN_DATA = 'retainData';

export const APP_ACCOUNT_FORENSIC_KMS_KEY_ALIAS = 'appForensicAliasKMS';

export const VOLATILITY3_SYMBOLS_PREFIX = 'vol3-symbols-key';

export const SSM_EXECUTION_TIMEOUT_CONTEXT_VALUE = 'ssmExecutionTimeout';

export const SSM_EXECUTION_TIMEOUT_ENV_VAR = 'SSM_EXECUTION_TIMEOUT';

export const APP_ACCOUNT_ASSUME_ROLE_NAME = 'ForensicEc2AllowAccessRole';

export const FORENSIC_INSTANCE_PROFILE = 'FORENSIC_INSTANCE_PROFILE';

/**
 * CloudWatch log group prefix for the output the SSM agent archives for every
 * command this solution sends.
 *
 * Must stay in step with SSM_OUTPUT_LOG_GROUP_PREFIX in
 * lambda/src/common/common.py: the Lambdas name the log group, and the instance
 * role is granted logs:CreateLogGroup on this prefix. If the two drift, the
 * agent is denied and the archiving silently stops happening again -
 * `test/ssm-output-log-group.test.ts` asserts they match.
 */
export const SSM_OUTPUT_LOG_GROUP_PREFIX = '/aws/ssm/forensic-orchestrator';

export const TOOLS_AMI = 'toolsAMI';

export const AMI_ID = 'amiID';

export const INSTANCE_TYPES = ['t3.large', 't3.xlarge'];

export const HYPHEN = /-/gi;

export const OS_TYPES = { LINUX: 'Linux' };

export const FORENSIC_ISOLATION_PROFILE_NAME = 'ForensicIsolationInstanceProfileName';

export interface ImageBuilderComponent {
    name: string;
    data: string;
}

/**
 * Default parent image for the forensic analysis AMI.
 *
 * Resolved through the AWS owned public SSM parameter rather than a per-region AMI id
 * map. EC2 Image Builder accepts `ssm:<parameter name or ARN>` for a recipe parent
 * image, so this keeps the recipe on the current Amazon Linux 2023 release in every
 * commercial region instead of pinning six regions to AMI ids that go stale.
 */
export const DEFAULT_PARENT_IMAGE_SSM_PARAMETER =
    '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64';

/**
 * Amazon Linux 2023 is the only supported parent OS for the analysis host. Every
 * investigation SSM document that runs on it installs packages with `yum` and manages
 * services with `systemctl`.
 */
export const DEFAULT_SUPPORTED_OS_VERSIONS = ['Amazon Linux 2023'];

/**
 * Root device of the Amazon Linux 2023 x86_64 AMI, which is also the device
 * `createForensicInstance` resizes when it launches an analysis instance.
 */
export const DEFAULT_ROOT_DEVICE_NAME = '/dev/xvda';

/**
 * Amazon Linux 2023 ships an 8 GiB root volume. The analysis image adds Docker plus a
 * pre-pulled log2timeline/plaso image, so the root volume has to grow before the build.
 */
export const DEFAULT_ROOT_VOLUME_SIZE_GIB = 30;

/**
 * Rebuild on the first of the month so the analysis host carries current Amazon Linux
 * 2023 patches, and only when the parent image or a component actually changed.
 */
export const DEFAULT_BUILD_SCHEDULE = 'cron(0 8 1 * ? *)';

export const IMAGE_BUILD_START_CONDITION =
    'EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE';

export interface SSMBuilderComponent {
    name: string;
    content: string;
    documentType: string;
    ssmDocumentName: string;
}

export interface PipelineConfig {
    /** Prefix applied to every EC2 Image Builder resource created for this pipeline. */
    name: string;
    /** Directory, relative to `source/`, holding the AWSTOE component documents. */
    dir: string;
    /** Name of the EC2 Image Builder image recipe. */
    cfnImageRecipeName: string;
    /**
     * Semantic version shared by the components and the recipe. Image Builder component
     * and recipe versions are immutable, so this has to be bumped whenever a file under
     * `dir` changes - otherwise the deployment fails because the version already exists.
     */
    version: string;
    /**
     * SSM parameter that resolves the parent image, without the `ssm:` prefix.
     * Defaults to {@link DEFAULT_PARENT_IMAGE_SSM_PARAMETER}.
     */
    parentImageSsmParameter?: string;
    /** OS versions the components declare support for. */
    supportedOsVersions?: string[];
    /** Instance types Image Builder may use for the build and test instances. */
    instanceTypes?: string[];
    /** Root device name of the parent image. */
    rootDeviceName?: string;
    /** Root volume size, in GiB, of the build instance and of the resulting AMI. */
    rootVolumeSizeGiB?: number;
    /**
     * cron or rate expression for scheduled rebuilds. Set to an empty string to create
     * the pipeline without a schedule and rebuild only on demand.
     */
    buildSchedule?: string;
    /**
     * Build the first image as part of `cdk deploy` so the AMI SSM parameter is populated
     * without an operator step. Adds the image build time to the deployment.
     */
    buildOnDeploy?: boolean;
    /**
     * SSM parameter the built AMI id is written to. Defaults to the `forensicImageName`
     * context value, which is what `createForensicInstance` reads.
     */
    ssmParameterName?: string;
}
