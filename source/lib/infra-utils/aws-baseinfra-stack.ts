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
import { RemovalPolicy, Stack } from 'aws-cdk-lib';
import {
    BastionHostLinux,
    FlowLogDestination,
    GatewayVpcEndpointAwsService,
    InterfaceVpcEndpoint,
    InterfaceVpcEndpointAwsService,
    InterfaceVpcEndpointService,
    ISecurityGroup,
    IVpc,
    NatProvider,
    Peer,
    Port,
    SecurityGroup,
    SubnetConfiguration,
    SubnetType,
    Vpc,
} from 'aws-cdk-lib/aws-ec2';
import {
    Effect,
    Policy,
    PolicyStatement,
    Role,
    ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

const defaultSubnetConfiguration = [
    {
        cidrMask: 24,
        name: 'externalDMZ',
        subnetType: SubnetType.PUBLIC,
    },
    {
        cidrMask: 24,
        name: 'service',
        subnetType: SubnetType.PRIVATE_WITH_EGRESS,
    },
    {
        cidrMask: 24,
        name: 'database',
        subnetType: SubnetType.PRIVATE_WITH_EGRESS,
    },
    {
        cidrMask: 24,
        name: 'internalDMZ',
        subnetType: SubnetType.PRIVATE_WITH_EGRESS,
    },
];

/**
 * Base infra props
 */
export interface BaseInfraProps {
    vpcCidr?: string;
    maxAZs?: number;
    subnetConfig?: [
        {
            cidrMask: number;
            name: string;
            subnetType: 'Public' | 'Private' | 'Isolated';
        }
    ];
    bastionInstance: boolean;
    enableVpcFlowLog: boolean;
    enableVPCEndpoints: boolean;
}

export class AWSBaseInfraConstruct extends Construct {
    public vpc: IVpc;
    constructor(scope: Construct, id: string, props: BaseInfraProps) {
        super(scope, id);

        const vpcCidr = props?.vpcCidr || Vpc.DEFAULT_CIDR_RANGE;
        const subnetConfig = (props?.subnetConfig ||
            defaultSubnetConfiguration) as SubnetConfiguration[];
        const maxAZs = props?.maxAZs || 2;

        this.vpc = new Vpc(this, 'vpc', {
            cidr: vpcCidr,
            enableDnsHostnames: true,
            enableDnsSupport: true,
            maxAzs: maxAZs,
            natGatewayProvider: NatProvider.gateway(),
            natGatewaySubnets: { subnetType: SubnetType.PUBLIC },
            natGateways: maxAZs,
            subnetConfiguration: subnetConfig,
            gatewayEndpoints: {
                S3: { service: GatewayVpcEndpointAwsService.S3 },
                DYNAMODB: { service: GatewayVpcEndpointAwsService.DYNAMODB },
            },
        });

        const vpcEndpointSecurityGroup = new SecurityGroup(this, `s3-vpc-endpoint-sg`, {
            vpc: this.vpc,
            allowAllOutbound: false,
        });

        vpcEndpointSecurityGroup.addIngressRule(
            Peer.ipv4(this.vpc.vpcCidrBlock),
            Port.tcp(443)
        );
        vpcEndpointSecurityGroup.addEgressRule(
            Peer.ipv4(this.vpc.vpcCidrBlock),
            Port.tcp(443)
        );

        // bastion box
        if (props?.bastionInstance) {
            const bastionHostLinux = new BastionHostLinux(this, 'bastion', {
                vpc: this.vpc,
            });
            bastionHostLinux.node.addDependency(this.vpc);
        }
        const infraConfig = new InfraConfig(this, 'InfraConfig');
        if (props?.enableVPCEndpoints) {
            infraConfig.enableVPCEndpoints(this.vpc, vpcEndpointSecurityGroup);
        }
        if (props?.enableVpcFlowLog) {
            infraConfig.enableVpcFlowLog(this.vpc);
        }
    }
}

export class InfraConfig extends Construct {
    constructor(scope: Construct, id: string) {
        super(scope, id);
    }

    public enableVPCEndpoints(vpc: IVpc, vpcEndPointSecurityGroup: ISecurityGroup) {
        const ec2Endpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointEC2', {
            service: InterfaceVpcEndpointAwsService.EC2,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });
        ec2Endpoint.node.addDependency(vpc);

        const ssmEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointSSM', {
            service: InterfaceVpcEndpointAwsService.SSM,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });
        ssmEndpoint.node.addDependency(vpc);

        const ssmMessageEndpoint = new InterfaceVpcEndpoint(
            this,
            'vpcEndpointSSMMessages',
            {
                service: InterfaceVpcEndpointAwsService.SSM_MESSAGES,
                vpc: vpc,
                lookupSupportedAzs: false,
                open: true,
                privateDnsEnabled: true,
                subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
                securityGroups: [vpcEndPointSecurityGroup],
            }
        );
        ssmMessageEndpoint.node.addDependency(vpc);

        const ec2MessageEndpoint = new InterfaceVpcEndpoint(
            this,
            'vpcEndpointEC2MESSAGES',
            {
                service: InterfaceVpcEndpointAwsService.EC2_MESSAGES,
                vpc: vpc,
                lookupSupportedAzs: false,
                open: true,
                privateDnsEnabled: true,
                subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
                securityGroups: [vpcEndPointSecurityGroup],
            }
        );
        ec2MessageEndpoint.node.addDependency(vpc);

        const lambdaEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointLambda', {
            service: InterfaceVpcEndpointAwsService.LAMBDA,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });

        lambdaEndpoint.node.addDependency(vpc);

        const snsEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointSNS', {
            service: InterfaceVpcEndpointAwsService.SNS,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });

        snsEndpoint.node.addDependency(vpc);

        const kmsEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointKMS', {
            service: InterfaceVpcEndpointAwsService.KMS,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });
        kmsEndpoint.node.addDependency(vpc);

        const cwLogsEndpoint = new InterfaceVpcEndpoint(
            this,
            'vpcEndpointCloudWatchLogs',
            {
                service: InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
                vpc: vpc,
                lookupSupportedAzs: false,
                open: true,
                privateDnsEnabled: true,
                subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
                securityGroups: [vpcEndPointSecurityGroup],
            }
        );
        cwLogsEndpoint.node.addDependency(vpc);

        const cwEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointCloudWatch', {
            service: InterfaceVpcEndpointAwsService.CLOUDWATCH,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });
        cwEndpoint.node.addDependency(vpc);

        const stsEndpoint = new InterfaceVpcEndpoint(this, 'vpcEndpointsts', {
            service: InterfaceVpcEndpointAwsService.STS,
            vpc: vpc,
            lookupSupportedAzs: false,
            open: true,
            privateDnsEnabled: true,
            subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [vpcEndPointSecurityGroup],
        });

        const securityHubEndpoint = new InterfaceVpcEndpoint(
            this,
            'vpcEndpointSecurityHub',
            {
                service: new InterfaceVpcEndpointService(
                    `com.amazonaws.${Stack.of(this).region}.securityhub`,
                    443
                ),
                vpc: vpc,
                lookupSupportedAzs: false,
                open: true,
                privateDnsEnabled: true,
                subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
                securityGroups: [vpcEndPointSecurityGroup],
            }
        );
        securityHubEndpoint.node.addDependency(vpc);
        stsEndpoint.node.addDependency(vpc);
    }

    public enableVpcFlowLog(vpc: IVpc) {
        const encryptionKey = new Key(this, 'VpcFlowLogsKey', {
            removalPolicy: RemovalPolicy.DESTROY,
            enableKeyRotation: true,
        });
        encryptionKey.addToResourcePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                sid: 'Allow VPC Flow Logs to use the key',
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

        const logGroup = new LogGroup(this, 'VpcFlowLogs', {
            retention: RetentionDays.TEN_YEARS,
            encryptionKey: encryptionKey,
        });

        const logGroupRole = new Role(this, 'VpcFlowLogsRole', {
            assumedBy: new ServicePrincipal('vpc-flow-logs.amazonaws.com'),
        });

        const logGroupPolicy = new Policy(this, 'VpcFlowLogsPolicy');

        logGroupPolicy.addStatements(
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:PutLogEvents',
                    'logs:DescribeLogGroups',
                    'logs:DescribeLogStreams',
                ],
                resources: [logGroup.logGroupArn],
            }),
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'kms:Encrypt*',
                    'kms:Decrypt*',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*',
                    'kms:Describe*',
                ],
                resources: [encryptionKey.keyArn],
            })
        );

        logGroupPolicy.attachToRole(logGroupRole);

        vpc.addFlowLog('FlowLogsToCloudWatch', {
            destination: FlowLogDestination.toCloudWatchLogs(logGroup, logGroupRole),
        });
    }
}
