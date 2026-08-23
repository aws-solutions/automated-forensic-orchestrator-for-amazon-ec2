#!/usr/bin/env node

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

import 'source-map-support/register';
import {
    DefaultStackSynthesizer,
    App,
    Aspects,
    Aws,
    Tags,
    Annotations,
} from 'aws-cdk-lib';
import { ForensicsSolutionsConstructsStack } from '../lib/forensic-solution-builder-stack';
import { AuthorizationType } from '../lib/infra-utils/aws-appsync-api';
import { ForensicsSecHubSolutionsConstructsStack } from '../lib/forensic-solution-builder-security-account-stack';
import { AwsSolutionsChecks, NagSuppressions } from 'cdk-nag';
import {
    ENV_NAME,
    SOLUTION_BUCKET,
    SOLUTION_ID,
    SOLUTION_NAME,
    SOLUTION_PROVIDER,
    SOLUTION_TMN,
    SOLUTION_VERSION,
} from '../lib/infra-utils/aws-solution-environment';
import {
    FORENSIC_BUCKET_COMPLIANCE_MODE,
    FORENSIC_BUCKET_RETENTION_DAYS,
    FORENSIC_BUCKET_ACCESS_IAM_ROLES_NAMES,
    FORENSIC_IMAGE_NAME_CONFIG,
    IMAGE_BUILDER_PIPELINE_CONFIG,
} from '../lib/infra-utils/infra-types';
import { CfnNagCustomResourceSuppressionAspect } from '../lib/infra-utils/cfn-nag-suppression';
import { ForensicImageBuilderStack } from '../lib/forensic-image-builder-stack';

const stackPrefix = 'Forensics-'.concat(ENV_NAME);
const accountId = Aws.ACCOUNT_ID;
const region = Aws.REGION;

const app = new App();

// On the app root rather than inside a target account branch: an aspect added to a single
// stack leaves every other stack unchecked, which is how ForensicSecHubStack shipped with
// no AwsSolutions coverage at all.
Aspects.of(app).add(new AwsSolutionsChecks());

const stackBuildTargetAcct =
    app.node.tryGetContext('STACK_BUILD_TARGET_ACCT') || 'forensicAccount';

const ec2ForensicImage = app.node.tryGetContext('ec2ForensicImage');

if (stackBuildTargetAcct == 'forensicAccount') {
    const forensicsSolutionsStack = new ForensicsSolutionsConstructsStack(
        app,
        'ForensicSolutionStack',
        {
            synthesizer: new DefaultStackSynthesizer({
                generateBootstrapVersionRule: false,
            }),
            description: `(${SOLUTION_ID}) - The AWS CDK template for deployment of the ${SOLUTION_NAME}, version: ${SOLUTION_VERSION}`,
            solutionId: SOLUTION_ID,
            solutionTradeMarkName: SOLUTION_TMN,
            solutionProvider: SOLUTION_PROVIDER,
            solutionBucket: SOLUTION_BUCKET,
            solutionName: SOLUTION_NAME,
            solutionVersion: SOLUTION_VERSION,
            stackPrefix: stackPrefix,
            env: {
                account: app.node.tryGetContext('account') || accountId,
                region: app.node.tryGetContext('region') || region,
            },
            forensicBucketRetentionDays:
                app.node.tryGetContext(FORENSIC_BUCKET_RETENTION_DAYS) || 30,
            forensicBucketComplianceMode:
                app.node.tryGetContext(FORENSIC_BUCKET_COMPLIANCE_MODE) || false,
            forensicBucketAccessIamRoleNames:
                app.node.tryGetContext(FORENSIC_BUCKET_ACCESS_IAM_ROLES_NAMES) || [],
            deployForensicApi: app.node.tryGetContext('deployApi') || false,
            apiNotifications: app.node.tryGetContext('apiNotifications') || false,
            wafAllowList: app.node.tryGetContext('apiAllowedIps'),
            wafRateLimit: app.node.tryGetContext('apiRateLimit'),
            apiAuthorizationConfig: {
                defaultAuthorization: {
                    authorizationType: AuthorizationType.IAM,
                },
            },
        }
    );
    NagSuppressions.addStackSuppressions(forensicsSolutionsStack, [
        {
            id: 'AwsSolutions-IAM5',
            reason: 'Uses service role - AWSLambdaVPCAccessExecutionRole and AWSLambdaBasicExecutionRole, Xray requires * permission, Allow key data access',
        },
        {
            // Two wildcards in this stack are functional requirements of
            // incident response rather than oversights, and both are documented
            // at the statement that grants them:
            //
            //   iam:PutRolePolicy on role/* - isolation attaches a deny-all
            //   policy to the compromised instance's role, which is not known
            //   until a finding arrives, and IAM has no condition key for an
            //   inline policy name.
            //
            //   ec2:RunInstances and ec2:CreateTags on * - the analysis host's
            //   AMI, subnet and security group are resolved at investigation
            //   time from SSM parameters and VPC lookups, so they cannot be
            //   named here. RunInstances is already conditioned on the region.
            //
            // Residual risk for both is recorded in the README security notes.
            id: 'AwsSolutions-IAM5',
            appliesTo: [
                'Action::iam:PutRolePolicy',
                'Action::ec2:RunInstances',
                'Action::ec2:CreateTags',
            ],
            reason:
                'Incident response cannot pre-name the compromised instance\'s role, '
                + 'nor the AMI, subnet and security group the analysis host is launched '
                + 'into, because both are resolved when a finding arrives. Scoped as far '
                + 'as IAM allows (account-qualified ARNs, region condition) and justified '
                + 'inline at each statement.',
        },
        {
            id: 'AwsSolutions-IAM4',
            reason: 'Uses service role - AWSLambdaVPCAccessExecutionRole and AWSLambdaBasicExecutionRole',
        },
        { id: 'AwsSolutions-L1', reason: 'node JS is still supported' },
        { id: 'AwsSolutions-S1', reason: 'Access logs bucket ' },
        { id: 'AwsSolutions-S2', reason: 'Access logs bucket ' },
        { id: 'AwsSolutions-S3', reason: 'Access logs bucket ' },
        { id: 'AwsSolutions-S10', reason: 'Access logs bucket ' },
        {
            id: 'AwsSolutions-SQS3',
            reason: 'It is a dead letter queue configured for lambda ',
        },
        {
            id: 'AwsSolutions-SQS4',
            reason: 'It is a dead letter queue configured for lambda ',
        },
        {
            id: 'AwsSolutions-EC23',
            reason: 'Isolation security group will be updated to restricted inbound access post assigning to EC2 by isolation lambda function',
        },
    ]);
    Aspects.of(forensicsSolutionsStack).add(new CfnNagCustomResourceSuppressionAspect());

    const imageBuilderPipelines = app.node.tryGetContext(IMAGE_BUILDER_PIPELINE_CONFIG);
    const buildsOwnForensicImage =
        Array.isArray(imageBuilderPipelines) && imageBuilderPipelines.length > 0;

    if (!ec2ForensicImage && !buildsOwnForensicImage) {
        // Only fatal when nothing will ever populate the AMI parameter. With an image
        // builder pipeline configured the AMI is produced by ForensicImageBuilderStack and
        // written straight into the parameter, so demanding an AMI id up front would make
        // the solution impossible to deploy from a clean account.
        //
        // Annotated on the stack, not on the app: the CLI reads error metadata off each
        // synthesized stack artifact, so an error on the App root is never printed and
        // never fails the synth.
        Annotations.of(forensicsSolutionsStack).addError(
            'Configuration forensicImage AMI ID is mandatory.  The investigation will fail'
        );
    }

    Tags.of(forensicsSolutionsStack).add('Solution-id', SOLUTION_ID);

    if (buildsOwnForensicImage) {
        const forensicImageBuilderStack = new ForensicImageBuilderStack(
            app,
            'ForensicImageBuilderStack',
            {
                synthesizer: new DefaultStackSynthesizer({
                    generateBootstrapVersionRule: false,
                }),
                description: `(${SOLUTION_ID}) - Forensic analysis AMI pipeline for the ${SOLUTION_NAME}, version: ${SOLUTION_VERSION}`,
                solutionId: SOLUTION_ID,
                solutionName: SOLUTION_NAME,
                solutionVersion: SOLUTION_VERSION,
                env: {
                    account: app.node.tryGetContext('account') || accountId,
                    region: app.node.tryGetContext('region') || region,
                },
                vpc: forensicsSolutionsStack.vpc,
                // Taken from context rather than from the StringParameter in the other
                // stack: both resolve to the same literal, but reading the construct
                // attribute would add a CloudFormation export of the parameter name and
                // block ForensicSolutionStack from ever replacing it.
                amiSsmParameterName: app.node.tryGetContext(FORENSIC_IMAGE_NAME_CONFIG),
                // An explicitly supplied AMI stays authoritative. Without this the next
                // scheduled rebuild would overwrite the operator's pinned AMI id and an
                // investigation would silently start using a different image.
                publishAmiIdToSsmParameter: !ec2ForensicImage,
            }
        );

        if (ec2ForensicImage) {
            Annotations.of(forensicImageBuilderStack).addWarning(
                `ec2ForensicImage is set to '${ec2ForensicImage}', so the image builder pipeline will build and publish an AMI but will not update the ${app.node.tryGetContext(
                    FORENSIC_IMAGE_NAME_CONFIG
                )} SSM parameter. Remove ec2ForensicImage to let the pipeline keep the analysis AMI current.`
            );
        }

        // The pipeline writes the built AMI id into the parameter ForensicSolutionStack
        // creates, so that stack has to exist first.
        forensicImageBuilderStack.addStackDependency(
            forensicsSolutionsStack,
            'the image distribution overwrites the AMI SSM parameter created by ForensicSolutionStack'
        );

        NagSuppressions.addStackSuppressions(forensicImageBuilderStack, [
            {
                id: 'AwsSolutions-IAM4',
                reason: 'The build instance profile uses AmazonSSMManagedInstanceCore and EC2InstanceProfileForImageBuilder, and the workflow execution role uses EC2ImageBuilderExecutionPolicy. These are the AWS managed policies EC2 Image Builder documents as the required grants for a build instance and an execution role; AWS maintains them as the service adds capabilities, so replacing them with hand written copies would silently break future builds. Both roles also carry an inline policy that this stack owns: on the build instance role it denies s3:GetObject on ISO objects, and on the execution role it denies iam:PassRole for every role except the build instance role and, unless ec2ForensicImage pins an AMI, allows ssm:GetParameter and ssm:PutParameter on the single AMI parameter. Neither managed policy grants access to the forensic evidence bucket, the case table or the forensic KMS keys.',
            },
        ]);

        Tags.of(forensicImageBuilderStack).add('Solution-id', SOLUTION_ID);
    }
}

if (stackBuildTargetAcct == 'securityHubAccount') {
    const forensicSecHubStack = new ForensicsSecHubSolutionsConstructsStack(
        app,
        'ForensicSecHubStack',
        {
            synthesizer: new DefaultStackSynthesizer({
                generateBootstrapVersionRule: false,
            }),
            description: `(${SOLUTION_ID}) - The AWS CDK template for deployment of the ${SOLUTION_NAME}, version: ${SOLUTION_VERSION}`,
            solutionId: SOLUTION_ID,
            solutionTradeMarkName: SOLUTION_TMN,
            solutionProvider: SOLUTION_PROVIDER,
            solutionName: SOLUTION_NAME,
            solutionVersion: SOLUTION_VERSION,
            stackPrefix: stackPrefix,
            env: {
                account: app.node.tryGetContext('sechubaccount') || accountId,
                region: app.node.tryGetContext('sechubregion') || region,
            },
        }
    );

    // Resource scoped rather than stack wide: everything else this stack creates is
    // expected to satisfy AwsSolutions on its own, and a stack level suppression would
    // hide the next finding that appears.
    NagSuppressions.addResourceSuppressionsByPath(
        forensicSecHubStack,
        'ForensicSecHubStack/ForensicSecurityHubConstruct/securityHubCustomAction/instanceIsolation/ExecutionRole/Resource',
        [
            {
                id: 'AwsSolutions-IAM4',
                reason: 'The custom action function writes its own log stream and runs in the forensic VPC, which is exactly what these two AWS managed service roles grant. AWSLambdaBasicExecutionRole is also what makes the redundant log group grant unnecessary in forensic_Custom_Action.',
                appliesTo: [
                    'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
                    'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
                ],
            },
        ]
    );
    NagSuppressions.addResourceSuppressionsByPath(
        forensicSecHubStack,
        'ForensicSecHubStack/ForensicSecurityHubConstruct/securityHubCustomAction/instanceIsolation/ExecutionRole/DefaultPolicy/Resource',
        [
            {
                id: 'AwsSolutions-IAM5',
                reason: 'xray:PutTraceSegments and xray:PutTelemetryRecords define no resource types in the IAM service authorization reference, so they can only be granted on *. The SQS grant in the same policy names the dead letter queue.',
                appliesTo: ['Resource::*'],
            },
        ]
    );
    NagSuppressions.addResourceSuppressionsByPath(
        forensicSecHubStack,
        'ForensicSecHubStack/ForensicSecurityHubConstruct/securityHubCustomAction/instanceIsolation/instanceIsolationFunction/Resource',
        [
            {
                id: 'AwsSolutions-L1',
                reason: 'python3.12 is a supported Lambda runtime. The shared dependency layer is built with --python-version 3.12 and manylinux wheels, so the runtime cannot move ahead of the layer independently: both change together, in aws-python-lambda-dependency-layer.ts.',
            },
        ]
    );

    Tags.of(forensicSecHubStack).add('Solution-id', SOLUTION_ID);
}
