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

import { readFileSync, readdirSync } from 'fs';
import * as path from 'path';
import { Annotations, CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import { IVpc, SecurityGroup, SubnetType } from 'aws-cdk-lib/aws-ec2';
import {
    CfnInstanceProfile,
    Effect,
    ManagedPolicy,
    PolicyStatement,
    Role,
    ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import {
    CfnComponent,
    CfnDistributionConfiguration,
    CfnImage,
    CfnImagePipeline,
    CfnImageRecipe,
    CfnInfrastructureConfiguration,
} from 'aws-cdk-lib/aws-imagebuilder';
import { Construct } from 'constructs';
import { addCfnSecurityGroup } from './infra-utils/cfn-nag-suppression';
import {
    DEFAULT_BUILD_SCHEDULE,
    DEFAULT_PARENT_IMAGE_SSM_PARAMETER,
    DEFAULT_ROOT_DEVICE_NAME,
    DEFAULT_ROOT_VOLUME_SIZE_GIB,
    DEFAULT_SUPPORTED_OS_VERSIONS,
    IMAGE_BUILD_START_CONDITION,
    IMAGE_BUILDER_PIPELINE_CONFIG,
    ImageBuilderComponent,
    INSTANCE_TYPES,
    OS_TYPES,
    PipelineConfig,
} from './infra-utils/infra-types';

/**
 * Hard limit on the inline AWSTOE document carried by
 * `AWS::ImageBuilder::Component.Data`. Breaching it fails CreateComponent, which fails
 * the deployment.
 */
const COMPONENT_DATA_LIMIT_BYTES = 16000;

/** Warn once an inlined component document passes this share of the limit. */
const COMPONENT_DATA_WARN_PERCENT = 90;

export interface ForensicImageBuilderStackProps extends StackProps {
    readonly description: string;
    readonly solutionId: string;
    readonly solutionName: string;
    readonly solutionVersion: string;
    /** VPC the build and test instances run in. Needs egress for dnf and the registry pull. */
    readonly vpc: IVpc;
    /**
     * SSM parameter `createForensicInstance` reads to find the analysis AMI. The image
     * distribution writes the built AMI id here, which is what removes the manual
     * "copy the AMI id into cdk.json" step.
     */
    readonly amiSsmParameterName: string;
    /**
     * Publish the built AMI id to {@link amiSsmParameterName}.
     *
     * Set to false when the operator pinned an AMI with the `ec2ForensicImage` context
     * value. The pipeline still builds and publishes an AMI, but it does not overwrite the
     * parameter, so an explicitly pinned image stays pinned instead of being replaced by
     * the next scheduled rebuild.
     */
    readonly publishAmiIdToSsmParameter: boolean;
}

/**
 * Builds the forensic analysis AMI that the investigation step function launches.
 *
 * Separate from `ForensicSolutionStack` on purpose: the AMI is rebuilt on its own cadence
 * (monthly, to pick up Amazon Linux 2023 patches) and a rebuild must never put the
 * evidence store, the DynamoDB case table or the step functions at risk.
 */
export class ForensicImageBuilderStack extends Stack {
    constructor(scope: Construct, id: string, props: ForensicImageBuilderStackProps) {
        super(scope, id, props);

        const pipelineConfigs = this.node.tryGetContext(
            IMAGE_BUILDER_PIPELINE_CONFIG
        ) as PipelineConfig[];

        if (!Array.isArray(pipelineConfigs) || pipelineConfigs.length === 0) {
            Annotations.of(this).addError(
                `Configuration ${IMAGE_BUILDER_PIPELINE_CONFIG} must be a non-empty list to build the forensic analysis AMI.`
            );
            return;
        }

        if (!props.amiSsmParameterName) {
            // Without it the distribution has nowhere to publish the AMI id, so the
            // investigation would keep launching whatever the placeholder points at.
            Annotations.of(this).addError(
                'Configuration forensicImageName is mandatory. It names the SSM parameter the built AMI id is published to and that createForensicInstance reads.'
            );
            return;
        }

        const subnetId = this.resolveBuildSubnetId(props.vpc);

        // No ingress at all: the build instance is driven by Systems Manager Run Command
        // from the Image Builder service, which needs egress only. Egress is open because
        // the build pulls Amazon Linux 2023 packages and the log2timeline/plaso image.
        const buildSecurityGroup = new SecurityGroup(this, 'ImageBuilderSecurityGroup', {
            vpc: props.vpc,
            allowAllOutbound: true,
            description:
                'Forensic analysis AMI build instance. Egress only - no inbound access.',
        });
        addCfnSecurityGroup(buildSecurityGroup);

        const build = this.createBuildInstanceProfile();
        const executionRole = this.createExecutionRole(
            props.amiSsmParameterName,
            props.publishAmiIdToSsmParameter,
            pipelineConfigs,
            build.instanceRole
        );

        pipelineConfigs.forEach((config) => {
            this.createPipeline(
                config,
                props,
                build.instanceProfile,
                executionRole,
                buildSecurityGroup,
                subnetId
            );
        });
    }

    /**
     * Dedicated instance profile for the build and test instances.
     *
     * `ForensicSolutionStack` already creates `InvestigationInstanceRole`, and that role
     * carries `EC2InstanceProfileForImageBuilder`, but it also grants read and write on
     * the forensic evidence bucket and on the volume encryption key. An image build
     * installs packages from the internet and pulls a third party container image, so
     * giving it a principal that can write to the chain-of-custody store would widen the
     * blast radius of a compromised upstream package to the evidence itself. This role is
     * therefore separate and carries no grant on the evidence bucket, on the case table or
     * on the forensic KMS keys.
     *
     * It is not, however, free of any reach into forensic data.
     * `EC2InstanceProfileForImageBuilder` (v12) additionally grants:
     *
     * - `s3:GetObject` on any `.iso`, `.ISO` or `.Iso` object in any bucket in this
     *   account (the resources are `arn:aws:s3:::<any bucket>/<any name>.iso` and its two
     *   case variants), which is intended for Windows ISO imports. The deny statement
     *   below removes it, because nothing in this build downloads an ISO.
     * - `ec2:DescribeVolumes` and `ec2:DescribeSnapshots` on `*`, which exposes the
     *   metadata (not the contents) of the volumes and snapshots an investigation
     *   creates. Both are needed by the AWSTOE agent and neither supports resource level
     *   permissions, so they stay.
     */
    private createBuildInstanceProfile(): {
        instanceRole: Role;
        instanceProfile: CfnInstanceProfile;
    } {
        const role = new Role(this, 'ImageBuilderInstanceRole', {
            assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
            description:
                'Forensic analysis AMI build instance. No grant on the forensic evidence bucket, the case table or the forensic KMS keys.',
        });

        // Lets the Image Builder service drive the build instance with Run Command.
        role.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')
        );
        // Grants the AWSTOE agent component download, snapshot creation and the
        // /aws/imagebuilder/* CloudWatch Logs writes that carry the build output.
        role.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('EC2InstanceProfileForImageBuilder')
        );

        // Trims the one grant in EC2InstanceProfileForImageBuilder that reaches buckets
        // this solution owns. An explicit deny always wins, including over any future
        // version of the managed policy, so the build instance cannot read an object out
        // of the evidence bucket by its extension. The build itself never downloads an
        // ISO: the component installs packages with dnf and pulls one container image.
        role.addToPolicy(
            new PolicyStatement({
                sid: 'DenyIsoDownloadFromAnyBucket',
                effect: Effect.DENY,
                actions: ['s3:GetObject'],
                resources: [
                    `arn:${this.partition}:s3:::*/*.iso`,
                    `arn:${this.partition}:s3:::*/*.ISO`,
                    `arn:${this.partition}:s3:::*/*.Iso`,
                ],
            })
        );

        return {
            instanceRole: role,
            instanceProfile: new CfnInstanceProfile(this, 'ImageBuilderInstanceProfile', {
                roles: [role.roleName],
                instanceProfileName: `ImageBuilderInstanceProfile-${
                    Stack.of(this).region
                }`,
            }),
        };
    }

    /**
     * Image Builder workflow execution role.
     *
     * Writing the output AMI id into a Parameter Store parameter needs `ssm:PutParameter`
     * on that parameter in the Image Builder execution role. The
     * `AWSServiceRoleForImageBuilder` service-linked role scopes `ssm:PutParameter` to
     * `parameter/imagebuilder/*` only, so distribution to the solution's own parameter
     * fails unless a custom execution role supplies it. AWS also recommends against
     * passing the service-linked role as the execution role, because a custom role keeps
     * service and resource control policies in effect for what Image Builder does on your
     * behalf.
     *
     * This role is *not* free of reach into the forensic account, and the separation that
     * applies to the build instance role does not apply here.
     * `EC2ImageBuilderExecutionPolicy` (v2) grants `iam:PassRole` on
     * `arn:aws:iam::*:role/*` conditioned only on `iam:PassedToService`, so without the
     * deny below anything able to drive this role could launch an instance carrying
     * `ForensicInstanceProfile-<region>` - that is `InvestigationInstanceRole`, which has
     * read and write on the evidence bucket and its KMS key. Two guardrails narrow that:
     *
     * 1. `iam:PassRole` is denied for every role except the build instance role, which
     *    holds no grant on the evidence store. An explicit deny wins over the managed
     *    policy, including over any future version of it that widens the allow.
     * 2. The trust policy pins `aws:SourceAccount` and `aws:SourceArn`, so only Image
     *    Builder image and pipeline resources created by this stack can cause the service
     *    to assume it. An unrelated Image Builder resource in the same account cannot.
     *
     * What remains: `ec2:RunInstances` on `arn:aws:ec2:*::snapshot/*` plus EBS scoped
     * `kms:Decrypt` are part of the managed policy and cannot be scoped by ARN, because
     * EC2 renders image and snapshot ARNs without an account id, so a policy cannot tell
     * this account's evidence snapshots from the Amazon owned parent image's snapshots.
     * A build definition that attaches an evidence snapshot to a build instance therefore
     * stays expressible. Restricting who may create Image Builder resources in the
     * forensic account is the control for that, not this policy.
     */
    private createExecutionRole(
        amiSsmParameterName: string,
        publishAmiIdToSsmParameter: boolean,
        pipelineConfigs: PipelineConfig[],
        buildInstanceRole: Role
    ): Role {
        const role = new Role(this, 'ImageBuilderExecutionRole', {
            assumedBy: new ServicePrincipal('imagebuilder.amazonaws.com', {
                conditions: {
                    StringEquals: {
                        'aws:SourceAccount': this.account,
                    },
                    ArnLike: {
                        'aws:SourceArn':
                            this.imageBuilderSourceArnPatterns(pipelineConfigs),
                    },
                },
            }),
            description:
                'Role EC2 Image Builder assumes to run the forensic analysis AMI build workflow. Can pass only the build instance role.',
        });

        // Same permissions the service-linked role grants, but under a role whose
        // permissions this stack owns and can extend. AWS documents attaching this policy
        // to a custom execution role as the supported alternative to passing the
        // service-linked role, and maintains it as the service gains capabilities.
        role.addManagedPolicy(
            ManagedPolicy.fromAwsManagedPolicyName('EC2ImageBuilderExecutionPolicy')
        );

        // The build only ever passes one role: the instance profile role the build and
        // test instances run under. Everything else - above all the investigation instance
        // role that can write the evidence bucket - is denied.
        role.addToPolicy(
            new PolicyStatement({
                sid: 'DenyPassRoleExceptTheBuildInstanceRole',
                effect: Effect.DENY,
                actions: ['iam:PassRole'],
                notResources: [buildInstanceRole.roleArn],
            })
        );

        if (publishAmiIdToSsmParameter) {
            role.addToPolicy(
                new PolicyStatement({
                    sid: 'PublishForensicAnalysisAmiIdToParameterStore',
                    effect: Effect.ALLOW,
                    actions: ['ssm:GetParameter', 'ssm:PutParameter'],
                    resources: [this.ssmParameterArn(amiSsmParameterName)],
                })
            );
        }

        return role;
    }

    /**
     * `aws:SourceArn` values the execution role's trust policy accepts.
     *
     * Image Builder passes the resource it is acting for when it assumes a role on your
     * behalf; AWS documents the same pair of conditions for the cross-account lifecycle
     * role, with the image ARN as the source. The image resource takes its name from the
     * recipe, and a scheduled run acts for the pipeline, so both shapes are listed.
     *
     * Names are lower cased because Image Builder ARNs are lower case - the documented
     * ARN patterns for these resource types accept `[a-z0-9-_]` only. If a build ever
     * fails with an AccessDenied on `sts:AssumeRole` for this role, the source ARN did not
     * match one of these patterns; log the denied ARN from CloudTrail and add its shape
     * here rather than dropping the conditions.
     */
    private imageBuilderSourceArnPatterns(pipelineConfigs: PipelineConfig[]): string[] {
        const arn = (resource: string) =>
            `arn:${this.partition}:imagebuilder:${this.region}:${this.account}:${resource}`;

        return pipelineConfigs.flatMap((config) => [
            arn(`image/${config.cfnImageRecipeName.toLowerCase()}/*`),
            arn(`image-pipeline/${config.name.toLowerCase()}-pipeline`),
        ]);
    }

    private createPipeline(
        config: PipelineConfig,
        props: ForensicImageBuilderStackProps,
        instanceProfile: CfnInstanceProfile,
        executionRole: Role,
        buildSecurityGroup: SecurityGroup,
        subnetId: string
    ): void {
        const components = this.loadComponents(config);

        if (components.length === 0) {
            Annotations.of(this).addError(
                `No AWSTOE component documents were found in '${config.dir}' for image builder pipeline '${config.name}'. The recipe would build an unmodified parent image with none of the tools the investigation documents need.`
            );
            return;
        }

        const supportedOsVersions =
            config.supportedOsVersions ?? DEFAULT_SUPPORTED_OS_VERSIONS;

        const componentConfigurations = components.map((component) => {
            this.assertWithinComponentDataLimit(config, component);

            const cfnComponent = new CfnComponent(
                this,
                `${config.name}-${component.name}-component`,
                {
                    name: `${config.name}-${component.name}`,
                    platform: OS_TYPES.LINUX,
                    version: config.version,
                    supportedOsVersions: supportedOsVersions,
                    description: `Forensic analysis host tooling for ${config.name}, from ${component.name}.yml`,
                    data: component.data,
                }
            );

            return { componentArn: cfnComponent.attrArn };
        });

        // `ssm:` tells Image Builder to resolve the parent image from Parameter Store at
        // build time, so a rebuild always starts from the current Amazon Linux 2023
        // release instead of an AMI id frozen into configuration.
        const parentImage = `ssm:${
            config.parentImageSsmParameter ?? DEFAULT_PARENT_IMAGE_SSM_PARAMETER
        }`;

        const recipe = new CfnImageRecipe(this, `${config.name}-recipe`, {
            name: config.cfnImageRecipeName,
            // Every other property of a recipe requires Replacement, and a recipe is
            // unique per name and version, so `version` in imageBuilderPipelines has to be
            // bumped in the same change as any edit to a component document under
            // `config.dir`. Editing a document produces a new component build version,
            // which changes `Components` here, which is a Replacement.
            version: config.version,
            parentImage: parentImage,
            components: componentConfigurations,
            // Deliberately free of the solution version. `Description`, `Name` and
            // `Version` all require Replacement, and `Name` and `Version` are fixed
            // literals, so any change to `Description` makes CloudFormation call
            // CreateImageRecipe again with a name and version that already exist -
            // ResourceAlreadyExistsException, UPDATE_FAILED, no new AMI. The solution
            // version therefore lives in `Tags`, which is a no interruption update.
            description:
                'Forensic analysis host for the Automated Forensics Orchestrator',
            tags: {
                SolutionName: props.solutionName,
                SolutionVersion: props.solutionVersion,
            },
            blockDeviceMappings: [
                {
                    deviceName: config.rootDeviceName ?? DEFAULT_ROOT_DEVICE_NAME,
                    ebs: {
                        volumeSize:
                            config.rootVolumeSizeGiB ?? DEFAULT_ROOT_VOLUME_SIZE_GIB,
                        volumeType: 'gp3',
                        deleteOnTermination: true,
                        // Encrypted with the account's default EBS encryption key. A
                        // customer managed key can be set here instead, but then the
                        // createForensicInstance execution role also needs kms:Decrypt
                        // and kms:CreateGrant on it or RunInstances is denied.
                        encrypted: true,
                    },
                },
            ],
            additionalInstanceConfiguration: {
                systemsManagerAgent: {
                    // The analysis host is driven entirely by Run Command, so the agent
                    // has to survive into the AMI.
                    uninstallAfterBuild: false,
                },
            },
        });

        const infrastructureConfiguration = new CfnInfrastructureConfiguration(
            this,
            `${config.name}-infrastructure`,
            {
                name: `${config.name}-infrastructure`,
                description: `Build and test environment for the ${config.name} AMI`,
                instanceProfileName: instanceProfile.ref,
                instanceTypes: config.instanceTypes ?? INSTANCE_TYPES,
                subnetId: subnetId,
                securityGroupIds: [buildSecurityGroup.securityGroupId],
                // Never leave a build instance running. Build output is in CloudWatch
                // Logs under /aws/imagebuilder/, so a failure is still diagnosable.
                terminateInstanceOnFailure: true,
                instanceMetadataOptions: {
                    httpTokens: 'required',
                },
                resourceTags: {
                    Purpose: 'ForensicAnalysisImageBuild',
                    'Solution-id': props.solutionId,
                },
            }
        );

        const ssmParameterName = config.ssmParameterName ?? props.amiSsmParameterName;

        const distributionConfiguration = new CfnDistributionConfiguration(
            this,
            `${config.name}-distribution`,
            {
                name: `${config.name}-distribution`,
                description: props.publishAmiIdToSsmParameter
                    ? `Publishes the ${config.name} AMI and records its id in ${ssmParameterName}`
                    : `Publishes the ${config.name} AMI. The AMI SSM parameter is left alone because ec2ForensicImage pins an AMI explicitly.`,
                distributions: [
                    {
                        region: Stack.of(this).region,
                        amiDistributionConfiguration: {
                            Description: `Forensic analysis host for the ${props.solutionName}, version ${props.solutionVersion}`,
                            AmiTags: {
                                Name: config.name,
                                Purpose: 'ForensicAnalysis',
                                'Solution-id': props.solutionId,
                                SolutionVersion: props.solutionVersion,
                            },
                        },
                        // This is what closes the loop. Image Builder writes the AMI id
                        // straight into the parameter createForensicInstance reads, so
                        // there is no ec2ForensicImage value to copy by hand. `text`
                        // matches the parameter ForensicSolutionStack creates; switch to
                        // `aws:ec2:image` to have Parameter Store validate the value as
                        // an AMI id.
                        ...(props.publishAmiIdToSsmParameter && {
                            ssmParameterConfigurations: [
                                {
                                    parameterName: ssmParameterName,
                                    dataType: 'text',
                                },
                            ],
                        }),
                    },
                ],
            }
        );

        const imageTestsConfiguration = {
            // The component's `test` phase boots the finished AMI and proves docker runs
            // log2timeline/plaso offline and that a Volatility 3 supported interpreter is
            // on PATH. Disabling this would ship an unverified analysis host.
            imageTestsEnabled: true,
            timeoutMinutes: 90,
        };

        const buildSchedule = config.buildSchedule ?? DEFAULT_BUILD_SCHEDULE;

        const pipeline = new CfnImagePipeline(this, `${config.name}-pipeline`, {
            name: `${config.name}-pipeline`,
            description: `Rebuilds the ${config.name} AMI so the analysis host carries current Amazon Linux 2023 patches`,
            imageRecipeArn: recipe.attrArn,
            infrastructureConfigurationArn: infrastructureConfiguration.attrArn,
            distributionConfigurationArn: distributionConfiguration.attrArn,
            executionRole: executionRole.roleArn,
            imageTestsConfiguration: imageTestsConfiguration,
            status: 'ENABLED',
            ...(buildSchedule && {
                schedule: {
                    scheduleExpression: buildSchedule,
                    // Only rebuild when Amazon Linux 2023 or a component actually moved,
                    // so a monthly schedule does not produce twelve identical AMIs a year.
                    pipelineExecutionStartCondition: IMAGE_BUILD_START_CONDITION,
                },
            }),
        });

        new CfnOutput(this, `${config.name}PipelineArn`, {
            value: pipeline.attrArn,
            description: `Run an on-demand rebuild with: aws imagebuilder start-image-pipeline-execution --image-pipeline-arn <this value>`,
        });

        new CfnOutput(this, `${config.name}AmiSsmParameter`, {
            value: props.publishAmiIdToSsmParameter ? ssmParameterName : 'not published',
            description: props.publishAmiIdToSsmParameter
                ? 'SSM parameter this pipeline publishes the forensic analysis AMI id to, and that createForensicInstance reads'
                : `This pipeline does not publish to ${ssmParameterName} because ec2ForensicImage pins an AMI. Remove that context value to let the pipeline own the parameter.`,
        });

        if (config.buildOnDeploy ?? true) {
            // A pipeline on its own only produces an AMI when its schedule next fires, so
            // a fresh deployment would leave the AMI parameter at its placeholder for up
            // to a month. Building one image as a stack resource makes the deployment
            // itself produce the AMI and populate the parameter, and makes a broken
            // component fail the deployment instead of failing an investigation later.
            const image = new CfnImage(this, `${config.name}-image`, {
                imageRecipeArn: recipe.attrArn,
                infrastructureConfigurationArn: infrastructureConfiguration.attrArn,
                distributionConfigurationArn: distributionConfiguration.attrArn,
                executionRole: executionRole.roleArn,
                imageTestsConfiguration: imageTestsConfiguration,
            });

            new CfnOutput(this, `${config.name}AmiId`, {
                value: image.attrImageId,
                description:
                    'AMI id of the forensic analysis image built by this deployment. Scheduled rebuilds publish newer AMIs and update the SSM parameter, so the parameter, not this output, is the source of truth.',
            });
        }
    }

    /**
     * Fail `cdk synth` when an inlined AWSTOE document breaches the hard 16,000 byte
     * limit on `AWS::ImageBuilder::Component.Data`, and warn while it is merely close.
     *
     * Image Builder rejects an oversized document at CreateComponent time, so without
     * this check the only signal is a failed deployment. The escape hatch is the `Uri`
     * property, which reads the document from S3 instead of inlining it.
     */
    private assertWithinComponentDataLimit(
        config: PipelineConfig,
        component: ImageBuilderComponent
    ): void {
        const bytes = Buffer.byteLength(component.data, 'utf8');
        const percentOfLimit = (bytes / COMPONENT_DATA_LIMIT_BYTES) * 100;
        const summary =
            `AWSTOE component document ${config.dir}/${component.name}.yml is ${bytes} bytes ` +
            `(${percentOfLimit.toFixed(
                1
            )}% of the ${COMPONENT_DATA_LIMIT_BYTES} byte AWS::ImageBuilder::Component.Data limit)`;

        if (bytes >= COMPONENT_DATA_LIMIT_BYTES) {
            Annotations.of(this).addError(
                `${summary}. Image Builder will reject it at CreateComponent time. ` +
                    `Split the build steps across a second document in ${config.dir}, or ` +
                    `stage the document in S3 and reference it with the component Uri property.`
            );
        } else if (percentOfLimit >= COMPONENT_DATA_WARN_PERCENT) {
            Annotations.of(this).addWarning(
                `${summary}. This leaves room for roughly ${
                    COMPONENT_DATA_LIMIT_BYTES - bytes
                } more bytes of build steps.`
            );
        }
    }

    /**
     * Loads every AWSTOE component document in the configured directory.
     */
    private loadComponents(config: PipelineConfig): ImageBuilderComponent[] {
        const componentDir = path.join(__dirname, '..', config.dir);

        return readdirSync(componentDir)
            .filter((fileName) => fileName.endsWith('.yml') || fileName.endsWith('.yaml'))
            .sort()
            .map((fileName) => ({
                name: fileName.replace(/\.ya?ml$/, ''),
                data: readFileSync(path.join(componentDir, fileName)).toString(),
            }));
    }

    /**
     * Build instances need egress for `dnf` and for the container registry pull, so they
     * go in a private subnet with a route to a NAT gateway.
     */
    private resolveBuildSubnetId(vpc: IVpc): string {
        const subnetIds = vpc.selectSubnets({
            subnetType: SubnetType.PRIVATE_WITH_EGRESS,
        }).subnetIds;

        if (subnetIds.length === 0) {
            Annotations.of(this).addError(
                'No private subnet with egress was found in the forensic VPC. The image build needs outbound access to install Amazon Linux 2023 packages and to pull the log2timeline/plaso image.'
            );
            return '';
        }

        return subnetIds[0];
    }

    private ssmParameterArn(parameterName: string): string {
        const name = parameterName.startsWith('/')
            ? parameterName.substring(1)
            : parameterName;

        return `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter/${name}`;
    }
}
