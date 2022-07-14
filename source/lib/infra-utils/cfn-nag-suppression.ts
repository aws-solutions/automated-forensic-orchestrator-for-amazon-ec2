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
import { IAspect, CfnResource } from 'aws-cdk-lib';
import { CfnPolicy, IPolicy, IRole } from 'aws-cdk-lib/aws-iam';
import { CfnSecurityGroup, ISecurityGroup } from 'aws-cdk-lib/aws-ec2';
import { ILogGroup } from 'aws-cdk-lib/aws-logs';
import { CfnBucket, IBucket } from 'aws-cdk-lib/aws-s3';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { CfnTable, ITable } from 'aws-cdk-lib/aws-dynamodb';

const METADATA_TYPE = 'cfn_nag';
const SUPRESSION_KEY = 'rules_to_suppress';

export interface CfnNagRuleSuppression {
    id: string;
    reason: string;
}

export const IAMPolicySuppressor = [
    {
        id: 'W76',
        reason: 'Combined all sub policies for the function as one inline policy. For operational ease!',
    },
    {
        id: 'W12',
        reason: 'Readonly access and Xray Put has * access https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html!',
    },
];

/**
 * Adds cfn nag suppressions to the given construct
 */
export const addCfnNagSuppressionMeta = (
    construct: CfnResource,
    rulesToSuppress: CfnNagRuleSuppression[]
): void => {
    construct.cfnOptions.metadata = {
        ...construct.cfnOptions.metadata,
        [METADATA_TYPE]: {
            ...construct.cfnOptions.metadata?.cfn_nag,
            [SUPRESSION_KEY]: [
                ...(construct.cfnOptions.metadata?.cfn_nag?.rules_to_suppress || []),
                ...rulesToSuppress,
            ],
        },
    };
};

export class CfnNagCustomResourceSuppressionAspect implements IAspect {
    public visit(construct: Construct): void {
        if (
            construct.node.path.endsWith('framework-onEvent/LogRetention/Resource') ||
            construct.node.path.endsWith('/framework-onEvent/Resource')
        ) {
            addCfnNagSuppressionMeta(construct as CfnResource, [
                {
                    id: 'W58',
                    reason: 'AWS Metrics function for sending reports',
                },
                {
                    id: 'W89',
                    reason: 'AWS Metrics function for sending reports not configured inside VPC',
                },
                {
                    id: 'W92',
                    reason: 'Can not change, this is CDK feature without any configuration ReservedConcurrentExecutions',
                },
            ]);
        }

        if (
            construct.node.path.endsWith('ForensicSolutionCloudTrail/LogGroup/Resource')
        ) {
            addCfnNagSuppressionMeta(construct as CfnResource, [
                {
                    id: 'W84',
                    reason: 'Cloudwatch logs - open to be debugged by third party log collector',
                },
            ]);
        }

        if (
            construct.node.path.endsWith('StateMachine/Role/DefaultPolicy/Resource') ||
            construct.node.path.endsWith('/ExecutionRole/DefaultPolicy/Resource') ||
            construct.node.path.endsWith('s3CopyRole/DefaultPolicy/Resource') ||
            construct.node.path.endsWith(
                'InvestigationInstanceRole/DefaultPolicy/Resource'
            ) ||
            construct.node.path.endsWith('createCustomActionPolicy/Resource')
        ) {
            addCfnNagSuppressionMeta(construct as CfnResource, [...IAMPolicySuppressor]);
        }
    }
}

export const addLogGroupSuppression = (forensicLogGroup: ILogGroup): void => {
    (forensicLogGroup.node.defaultChild as CfnResource).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W84',
                    reason: 'Cloudwatch logs - open to be debugged by third party log collector',
                },
            ],
        },
    };
};

export const accessLogsBucketCfnNagSuppression = (accessLogsBucket: IBucket): void => {
    (accessLogsBucket.node.defaultChild as CfnBucket).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W35',
                    reason: 'No need to enable access logs on the access log bucket!',
                },
                {
                    id: 'W51',
                    reason: 'No need to have bucket policy for the access log bucket!',
                },
                {
                    id: 'W41',
                    reason: 'No need to have bucket encryption for the access log bucket!',
                },
            ],
        },
    };
};

export const addIAMPolicyCfnNagSuppressor = (assumeRoleIAMPolicy: IPolicy): void => {
    (assumeRoleIAMPolicy.node.defaultChild as CfnPolicy).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [...IAMPolicySuppressor],
        },
    };
};

export const addCfnSecurityGroup = (allAllTrafficSG: ISecurityGroup): void => {
    (allAllTrafficSG.node.defaultChild as CfnSecurityGroup).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W40',
                    reason: 'It is for Lambda to AWS services and AWS service to AWS Service calls low risk',
                },
                {
                    id: 'W5',
                    reason: 'Very hard to narrow down the destination address for egress, We controlling ingress and also have IAM control on resources.',
                },
            ],
        },
    };
};

export const addIsolationCfnSecurityGroup = (allAllTrafficSG: ISecurityGroup): void => {
    (allAllTrafficSG.node.defaultChild as CfnSecurityGroup).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W40',
                    reason: 'It is for Lambda to AWS services and AWS service to AWS Service calls low risk',
                },
                {
                    id: 'W5',
                    reason: 'Very hard to narrow down the destination address for egress, We controlling ingress and also have IAM control on resources.',
                },
                {
                    id: 'W42',
                    reason: 'Isolation securitygroup to drain connection - by covert all traffic to untracked.',
                },

                {
                    id: 'W9',
                    reason: 'Isolation securitygroup to drain connection - by covert all traffic to untracked.',
                },
                {
                    id: 'W29',
                    reason: 'Very hard to narrow down the destination address for egress, We controlling ingress and also have IAM control on resources.',
                },
                {
                    id: 'W2',
                    reason: 'Isolation securitygroup to drain connection - by covert all traffic to untracked',
                },
            ],
        },
    };
};

export const addCfnSuppressionIAMPolicy = (role: IRole): void => {
    (role?.node.defaultChild as CfnResource).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W28',
                    reason: 'Need Roles Names to be unique used for cross account access!',
                },
                {
                    id: 'W76',
                    reason: 'Combined all sub policies for the function as one inline policy. For operational ease!',
                },
                {
                    id: 'W12',
                    reason: 'Readonly access and Xray Put has * access https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html!',
                },
            ],
        },
    };
};

export const addLambdaFunctionCfnNagSuppression = (lambdaFunction: IFunction): void => {
    (lambdaFunction.node.defaultChild as CfnResource).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W92',
                    reason: 'ReservedConcurrentExecutions is customer specific and customer can update them!',
                },
                {
                    id: 'W58',
                    reason: 'All Lambda functions have write access to cloudwatch logs - false positive!',
                },
                {
                    id: 'W40',
                    reason: 'It is for Lambda to AWS services and AWS service to AWS Service calls low risk',
                },
                {
                    id: 'W5',
                    reason: 'Very hard to narrow down the destination address for egress, We controlling ingress and also have IAM control on resources.',
                },
            ],
        },
    };
};

export const addCFNNagSuppressionTableName = (forensicInstanceTable: ITable): void => {
    (forensicInstanceTable.node.defaultChild as CfnTable).cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [
                {
                    id: 'W28',
                    reason: 'Need Table Name to be unique!',
                },
            ],
        },
    };
};
