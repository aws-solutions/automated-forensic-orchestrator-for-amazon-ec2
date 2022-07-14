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

export const VOL2_PROFILES_BUCKET = 'vol2ProfilesBucket';

export const DISK_SIZE = '512';

export const DISK_SIZE_CONFIG = 'diskSize';

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

export const VOLATILITY2_PROFILES_PREFIX = 'vol2-profiles-key';

export const SSM_EXECUTION_TIMEOUT_CONTEXT_VALUE = 'ssmExecutionTimeout';

export const SSM_EXECUTION_TIMEOUT_ENV_VAR = 'SSM_EXECUTION_TIMEOUT';

export const APP_ACCOUNT_ASSUME_ROLE_NAME = 'ForensicEc2AllowAccessRole';

export const FORENSIC_INSTANCE_PROFILE = 'FORENSIC_INSTANCE_PROFILE';

export const TOOLS_AMI = 'toolsAMI';

export const AMI_ID = 'amiID';

export const INSTANCE_TYPES = ['t3.large', 't3.xlarge'];

export const HYPHEN = /-/gi;

export const OS_TYPES = { LINUX: 'Linux' };

export interface ImageBuilderComponent {
    name: string;
    data: string;
}

export interface SSMBuilderComponent {
    name: string;
    content: string;
    documentType: string;
    ssmDocumentName: string;
}

export interface PipelineConfig {
    name: string;
    dir: string;
    instanceProfileName: string;
    cfnImageRecipeName: string;
    version: string;
    parentImage: Record<string, string>;
}
