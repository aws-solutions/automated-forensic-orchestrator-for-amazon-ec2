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

import * as fs from 'fs';
import * as path from 'path';
import { Annotations, Match, Template } from 'aws-cdk-lib/assertions';
import { App, Stack } from 'aws-cdk-lib';
import { Vpc } from 'aws-cdk-lib/aws-ec2';

import { ForensicImageBuilderStack } from '../lib/forensic-image-builder-stack';
import {
    DEFAULT_PARENT_IMAGE_SSM_PARAMETER,
    PipelineConfig,
} from '../lib/infra-utils/infra-types';
import {
    SOLUTION_ID,
    SOLUTION_NAME,
    SOLUTION_VERSION,
} from '../lib/infra-utils/aws-solution-environment';

const AMI_SSM_PARAMETER = 'forensic-analysis-ami';

const defaultPipelineConfig: PipelineConfig = {
    name: 'forensic-analysis',
    dir: './image-builder-components',
    cfnImageRecipeName: 'forensic-analysis-al2023',
    version: '1.0.0',
    parentImageSsmParameter: DEFAULT_PARENT_IMAGE_SSM_PARAMETER,
    instanceTypes: ['t3.large', 't3.xlarge'],
    rootVolumeSizeGiB: 30,
    buildSchedule: 'cron(0 8 1 * ? *)',
    buildOnDeploy: true,
};

const buildStack = (
    pipelineConfigs: unknown,
    amiSsmParameterName: string = AMI_SSM_PARAMETER,
    publishAmiIdToSsmParameter: boolean = true
): ForensicImageBuilderStack => {
    const app = new App({
        context: {
            imageBuilderPipelines: pipelineConfigs,
        },
    });

    // The real deployment hands in the forensic VPC. A throwaway stack keeps this test
    // independent of ForensicSolutionStack while still exercising subnet selection.
    const vpcStack = new Stack(app, 'VpcStack', {
        env: { account: '123456789012', region: 'us-east-1' },
    });
    const vpc = new Vpc(vpcStack, 'vpc', { maxAzs: 2 });

    return new ForensicImageBuilderStack(app, 'ForensicImageBuilderStack', {
        description: 'test',
        solutionId: SOLUTION_ID,
        solutionName: SOLUTION_NAME,
        solutionVersion: SOLUTION_VERSION,
        env: { account: '123456789012', region: 'us-east-1' },
        vpc: vpc,
        amiSsmParameterName: amiSsmParameterName,
        publishAmiIdToSsmParameter: publishAmiIdToSsmParameter,
    });
};

// `loadComponents` resolves `dir` against `source/`, the same as the real cdk.json value.
const OVERSIZED_DIR = './test/oversized-component-fixture';
const OVERSIZED_FIXTURE = path.resolve(__dirname, 'oversized-component-fixture');

describe('ForensicImageBuilderStack', () => {
    beforeAll(() => {
        // 16,001 bytes of valid YAML comment: one byte past what CreateComponent accepts
        // for an inlined document.
        fs.mkdirSync(OVERSIZED_FIXTURE, { recursive: true });
        fs.writeFileSync(
            path.join(OVERSIZED_FIXTURE, 'too-big.yml'),
            `name: TooBig\n${'# padding\n'.repeat(1600)}`
        );
    });

    afterAll(() => {
        fs.rmSync(OVERSIZED_FIXTURE, { recursive: true, force: true });
    });

    test('creates the full Image Builder resource set', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.resourceCountIs('AWS::ImageBuilder::Component', 1);
        template.resourceCountIs('AWS::ImageBuilder::ImageRecipe', 1);
        template.resourceCountIs('AWS::ImageBuilder::InfrastructureConfiguration', 1);
        template.resourceCountIs('AWS::ImageBuilder::DistributionConfiguration', 1);
        template.resourceCountIs('AWS::ImageBuilder::ImagePipeline', 1);
        template.resourceCountIs('AWS::ImageBuilder::Image', 1);
    });

    test('resolves the parent image from an SSM parameter, not a per-region AMI id', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::ImageRecipe', {
            ParentImage: `ssm:${DEFAULT_PARENT_IMAGE_SSM_PARAMETER}`,
            Version: '1.0.0',
            Name: 'forensic-analysis-al2023',
        });
    });

    test('grows the Amazon Linux 2023 root volume and encrypts it', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::ImageRecipe', {
            BlockDeviceMappings: [
                {
                    // Same device createForensicInstance resizes when it launches the
                    // analysis instance.
                    DeviceName: '/dev/xvda',
                    Ebs: {
                        VolumeSize: 30,
                        VolumeType: 'gp3',
                        Encrypted: true,
                        DeleteOnTermination: true,
                    },
                },
            ],
        });
    });

    test('keeps the SSM agent in the AMI so Run Command can drive the analysis host', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::ImageRecipe', {
            AdditionalInstanceConfiguration: {
                SystemsManagerAgent: { UninstallAfterBuild: false },
            },
        });
    });

    test('publishes the built AMI id to the parameter createForensicInstance reads', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::DistributionConfiguration', {
            Distributions: [
                Match.objectLike({
                    Region: 'us-east-1',
                    SsmParameterConfigurations: [
                        { ParameterName: AMI_SSM_PARAMETER, DataType: 'text' },
                    ],
                }),
            ],
        });
    });

    // The partition stays a pseudo parameter, so the ARN synthesises as an Fn::Join.
    const parameterArnJoin = (parameterPath: string) => ({
        'Fn::Join': [
            '',
            [
                'arn:',
                { Ref: 'AWS::Partition' },
                `:ssm:us-east-1:123456789012:parameter/${parameterPath}`,
            ],
        ],
    });

    test('gives the execution role PutParameter on exactly that parameter', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::IAM::Policy', {
            PolicyDocument: Match.objectLike({
                Statement: Match.arrayWith([
                    {
                        Sid: 'PublishForensicAnalysisAmiIdToParameterStore',
                        Action: ['ssm:GetParameter', 'ssm:PutParameter'],
                        Effect: 'Allow',
                        Resource: parameterArnJoin(AMI_SSM_PARAMETER),
                    },
                ]),
            }),
        });
    });

    test('strips the leading slash when building the parameter ARN', () => {
        const template = Template.fromStack(
            buildStack([defaultPipelineConfig], '/forensic/analysis-ami')
        );

        template.hasResourceProperties('AWS::IAM::Policy', {
            PolicyDocument: Match.objectLike({
                Statement: Match.arrayWith([
                    Match.objectLike({
                        Resource: parameterArnJoin('forensic/analysis-ami'),
                    }),
                ]),
            }),
        });
    });

    test('runs the build in a private subnet with IMDSv2 required and no inbound access', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::InfrastructureConfiguration', {
            InstanceMetadataOptions: { HttpTokens: 'required' },
            InstanceTypes: ['t3.large', 't3.xlarge'],
            TerminateInstanceOnFailure: true,
        });

        template.hasResourceProperties('AWS::EC2::SecurityGroup', {
            SecurityGroupIngress: Match.absent(),
        });
    });

    test('enables the image tests that prove plaso runs on the finished AMI', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::ImageBuilder::ImagePipeline', {
            ImageTestsConfiguration: { ImageTestsEnabled: true, TimeoutMinutes: 90 },
            Status: 'ENABLED',
            Schedule: {
                ScheduleExpression: 'cron(0 8 1 * ? *)',
                PipelineExecutionStartCondition:
                    'EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE',
            },
        });
    });

    test('reuses one build instance profile and one execution role for the pipeline', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.resourceCountIs('AWS::IAM::InstanceProfile', 1);
        template.resourceCountIs('AWS::IAM::Role', 2);
        template.hasResourceProperties('AWS::IAM::Role', {
            AssumeRolePolicyDocument: Match.objectLike({
                Statement: Match.arrayWith([
                    Match.objectLike({
                        Principal: { Service: 'imagebuilder.amazonaws.com' },
                    }),
                ]),
            }),
        });
    });

    // EC2ImageBuilderExecutionPolicy grants iam:PassRole on arn:aws:iam::*:role/* with only
    // an iam:PassedToService condition, so without this deny anything able to drive the
    // execution role could launch an instance carrying InvestigationInstanceRole, which has
    // read and write on the evidence bucket and its KMS key.
    test('execution role can pass no role other than the build instance role', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::IAM::Policy', {
            PolicyDocument: Match.objectLike({
                Statement: Match.arrayWith([
                    {
                        Sid: 'DenyPassRoleExceptTheBuildInstanceRole',
                        Effect: 'Deny',
                        Action: 'iam:PassRole',
                        NotResource: {
                            'Fn::GetAtt': [
                                Match.stringLikeRegexp('ImageBuilderInstanceRole'),
                                'Arn',
                            ],
                        },
                    },
                ]),
            }),
            Roles: [{ Ref: Match.stringLikeRegexp('ImageBuilderExecutionRole') }],
        });
    });

    test('execution role trust policy is pinned to this account and to this stack', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::IAM::Role', {
            AssumeRolePolicyDocument: Match.objectLike({
                Statement: [
                    Match.objectLike({
                        Principal: { Service: 'imagebuilder.amazonaws.com' },
                        Condition: {
                            StringEquals: { 'aws:SourceAccount': '123456789012' },
                            ArnLike: {
                                'aws:SourceArn': [
                                    {
                                        'Fn::Join': [
                                            '',
                                            [
                                                'arn:',
                                                { Ref: 'AWS::Partition' },
                                                ':imagebuilder:us-east-1:123456789012:image/forensic-analysis-al2023/*',
                                            ],
                                        ],
                                    },
                                    {
                                        'Fn::Join': [
                                            '',
                                            [
                                                'arn:',
                                                { Ref: 'AWS::Partition' },
                                                ':imagebuilder:us-east-1:123456789012:image-pipeline/forensic-analysis-pipeline',
                                            ],
                                        ],
                                    },
                                ],
                            },
                        },
                    }),
                ],
            }),
        });
    });

    // EC2InstanceProfileForImageBuilder grants s3:GetObject on any .iso object in any
    // bucket in the account. Nothing in this build downloads an ISO.
    test('build instance cannot read an ISO object out of any bucket', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        template.hasResourceProperties('AWS::IAM::Policy', {
            PolicyDocument: Match.objectLike({
                Statement: [
                    Match.objectLike({
                        Sid: 'DenyIsoDownloadFromAnyBucket',
                        Effect: 'Deny',
                        Action: 's3:GetObject',
                    }),
                ],
            }),
            Roles: [{ Ref: Match.stringLikeRegexp('ImageBuilderInstanceRole') }],
        });
    });

    test('neither role claims to have no reach into forensic data', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        Object.values(template.findResources('AWS::IAM::Role')).forEach((role) => {
            expect(role.Properties.Description).not.toContain(
                'No access to forensic evidence'
            );
        });
    });

    // A recipe is unique per name and version, and every property except Tags requires
    // Replacement, so the solution version cannot live in the Description: a release bump
    // with no component change would call CreateImageRecipe with a name and version that
    // already exist and fail the stack update.
    test('keeps the solution version out of every recipe property that requires replacement', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        const recipes = Object.values(
            template.findResources('AWS::ImageBuilder::ImageRecipe')
        );
        expect(recipes).toHaveLength(1);

        const properties = recipes[0].Properties;
        expect(properties.Description).not.toContain(SOLUTION_VERSION);
        expect(properties.Name).not.toContain(SOLUTION_VERSION);
        expect(properties.Version).toEqual('1.0.0');
        expect(properties.Tags).toEqual({
            SolutionName: SOLUTION_NAME,
            SolutionVersion: SOLUTION_VERSION,
        });
    });

    test('warns while the inlined component document is close to the 16,000 byte limit', () => {
        const stack = buildStack([defaultPipelineConfig]);

        Annotations.fromStack(stack).hasWarning(
            '*',
            Match.stringLikeRegexp(
                'forensic-analysis-tools.yml is \\d+ bytes .*% of the 16000 byte'
            )
        );
    });

    test('errors instead of deploying an oversized component document', () => {
        const stack = buildStack([{ ...defaultPipelineConfig, dir: OVERSIZED_DIR }]);

        Annotations.fromStack(stack).hasError(
            '*',
            Match.stringLikeRegexp('Image Builder will reject it at CreateComponent time')
        );
    });

    test('component targets Amazon Linux 2023 and installs what the SSM documents call', () => {
        const template = Template.fromStack(buildStack([defaultPipelineConfig]));

        const components = template.findResources('AWS::ImageBuilder::Component');
        const component = Object.values(components)[0];

        expect(component.Properties.Platform).toEqual('Linux');
        expect(component.Properties.SupportedOsVersions).toEqual(['Amazon Linux 2023']);

        const data: string = component.Properties.Data;
        // These are the tools the investigation documents invoke on the analysis host.
        ['docker', 'git', 'jq', 'unzip', 'gzip', 'e2fsprogs', 'python3-pip'].forEach(
            (tool) => expect(data).toContain(tool)
        );
        expect(data).toContain('log2timeline/plaso');
        // The build must refuse a non Amazon Linux 2023 parent image, because the
        // documents shell out to yum and systemctl.
        expect(data).toContain('RequireAmazonLinux2023');
    });

    test('omits the schedule when buildSchedule is blank', () => {
        const template = Template.fromStack(
            buildStack([{ ...defaultPipelineConfig, buildSchedule: '' }])
        );

        template.hasResourceProperties('AWS::ImageBuilder::ImagePipeline', {
            Schedule: Match.absent(),
        });
    });

    test('omits the deploy time image build when buildOnDeploy is false', () => {
        const template = Template.fromStack(
            buildStack([{ ...defaultPipelineConfig, buildOnDeploy: false }])
        );

        template.resourceCountIs('AWS::ImageBuilder::Image', 0);
        template.resourceCountIs('AWS::ImageBuilder::ImagePipeline', 1);
    });

    test('falls back to the Amazon Linux 2023 parameter when none is configured', () => {
        const config = { ...defaultPipelineConfig };
        delete config.parentImageSsmParameter;

        const template = Template.fromStack(buildStack([config]));

        template.hasResourceProperties('AWS::ImageBuilder::ImageRecipe', {
            ParentImage: `ssm:${DEFAULT_PARENT_IMAGE_SSM_PARAMETER}`,
        });
    });

    // ec2ForensicImage has to keep working as an override, which means a scheduled rebuild
    // must not overwrite the AMI id an operator pinned deliberately.
    describe('when ec2ForensicImage pins an AMI', () => {
        test('does not publish the built AMI id to the parameter', () => {
            const template = Template.fromStack(
                buildStack([defaultPipelineConfig], AMI_SSM_PARAMETER, false)
            );

            template.hasResourceProperties(
                'AWS::ImageBuilder::DistributionConfiguration',
                {
                    Distributions: [
                        Match.objectLike({
                            SsmParameterConfigurations: Match.absent(),
                        }),
                    ],
                }
            );
        });

        test('drops PutParameter from the execution role', () => {
            const template = Template.fromStack(
                buildStack([defaultPipelineConfig], AMI_SSM_PARAMETER, false)
            );

            // The PassRole and ISO guardrails stay; only the Parameter Store grant goes.
            const statements = Object.values(
                template.findResources('AWS::IAM::Policy')
            ).flatMap((policy) => policy.Properties.PolicyDocument.Statement);

            expect(
                statements.filter((statement) => statement.Effect === 'Allow')
            ).toHaveLength(0);
            expect(JSON.stringify(statements)).not.toContain('ssm:PutParameter');
        });

        test('still builds the AMI so it is ready to switch to', () => {
            const template = Template.fromStack(
                buildStack([defaultPipelineConfig], AMI_SSM_PARAMETER, false)
            );

            template.resourceCountIs('AWS::ImageBuilder::Image', 1);
            template.resourceCountIs('AWS::ImageBuilder::ImagePipeline', 1);
        });
    });

    test('errors instead of silently creating nothing when no pipeline is configured', () => {
        const stack = buildStack([]);

        Annotations.fromStack(stack).hasError(
            '*',
            Match.stringLikeRegexp('imageBuilderPipelines must be a non-empty list')
        );
    });

    test('errors when the AMI SSM parameter name is missing', () => {
        const stack = buildStack([defaultPipelineConfig], '');

        Annotations.fromStack(stack).hasError(
            '*',
            Match.stringLikeRegexp('forensicImageName is mandatory')
        );
    });
});
