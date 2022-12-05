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
import { Annotations, Duration, Stack } from 'aws-cdk-lib';
import { Dashboard, GraphWidget, TextWidget } from 'aws-cdk-lib/aws-cloudwatch';
import { ManagedPolicy, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { IVpc, Peer, Port, SecurityGroup, SubnetType } from 'aws-cdk-lib/aws-ec2';
import {
    Code,
    CodeSigningConfig,
    Function,
    FunctionProps,
    IFunction,
    LayerVersion,
    Tracing,
} from 'aws-cdk-lib/aws-lambda';
import { Platform, SigningProfile } from 'aws-cdk-lib/aws-signer';
import * as child_process from 'child_process';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';
import {
    DEFAULT_PYTHON_VERSION,
    getPythonCommonDependencyLayer,
} from './aws-python-lambda-dependency-layer';
import { SOLUTION_ID, SOLUTION_VERSION } from './aws-solution-environment';
import {
    addCfnSecurityGroup,
    addCfnSuppressionIAMPolicy,
    addLambdaFunctionCfnNagSuppression,
} from './cfn-nag-suppression';
export type PythonFunctionProps = Omit<
    FunctionProps,
    'runtime' | 'code' | 'role' | 'vpc'
> & {
    sourceCodePath?: string;
    applicationName: string;
    dashboard?: Dashboard;
    skipCodeSigning?: boolean;
    vpc: IVpc;
};

/**
 * Python lambda construct
 * This construct creates/reuses common layer if no specific requirement spec set
 */
export class PythonLambdaConstruct extends Construct {
    private readonly LAMBDA_RELATIVE_PATH = '../../lambda';
    public readonly function: IFunction;
    public readonly defaultSecurityGroup: SecurityGroup;
    constructor(scope: Construct, id: string, props: PythonFunctionProps) {
        super(scope, id);

        const functionRole = new Role(this, 'ExecutionRole', {
            assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
            roleName: `${props.applicationName}-${Stack.of(this).region}-Role`,
            description: `Lambda execution role for function`,
            managedPolicies: [
                ManagedPolicy.fromAwsManagedPolicyName(
                    'service-role/AWSLambdaBasicExecutionRole'
                ),
                // must to have this one for lambda to run in VPC
                ManagedPolicy.fromAwsManagedPolicyName(
                    'service-role/AWSLambdaVPCAccessExecutionRole'
                ),
            ],
        });

        this.defaultSecurityGroup = new SecurityGroup(this, 'SecurityGroup', {
            vpc: props.vpc,
            description: 'Security group for Forensic Lambda Function ',
            allowAllOutbound: true,
        });

        this.defaultSecurityGroup.addIngressRule(
            Peer.ipv4(props.vpc.vpcCidrBlock),
            Port.tcp(443)
        );
        this.defaultSecurityGroup.addEgressRule(
            Peer.ipv4(props.vpc.vpcCidrBlock),
            Port.tcp(443)
        );
        const resourceCodePath =
            props.sourceCodePath ?? path.resolve(__dirname, this.LAMBDA_RELATIVE_PATH);

        // Development escape
        const skipCodeSigning =
            props.skipCodeSigning || !!this.node.tryGetContext('skipCodeSigning');

        this.function = new Function(this, `${id}Function`, {
            ...(!skipCodeSigning && {
                codeSigningConfig: this.createCodeSigningConfig(),
            }),
            code: Code.fromAsset(resourceCodePath, { exclude: ['tests'] }),
            timeout: Duration.seconds(900),
            runtime: DEFAULT_PYTHON_VERSION,
            memorySize: 1024,
            tracing: Tracing.ACTIVE,
            role: functionRole,
            securityGroups: [this.defaultSecurityGroup],
            vpcSubnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
            layers: [
                this.createDependencyLayer(id, props.applicationName),
                ...(props.layers ?? []),
            ],
            deadLetterQueueEnabled: true,
            environment: {
                ...props.environment,
                SOLUTION_VERSION: SOLUTION_VERSION,
                SOLUTION_ID: SOLUTION_ID,
            },
            ...props,
        });

        addLambdaFunctionCfnNagSuppression(this.function);
        addCfnSecurityGroup(this.defaultSecurityGroup);

        addCfnSuppressionIAMPolicy(this.function.role!);

        if (props.dashboard) {
            // Create CloudWatch Dashboard Widgets: Errors, Invocations, Duration, Throttles

            props.dashboard.addWidgets(
                // Create Title for Dashboard
                new TextWidget({
                    markdown: `# Dashboard: ${this.function.functionName}`,
                    height: 1,
                    width: 24,
                }),
                new GraphWidget({
                    title: 'Invocations',
                    left: [this.function.metricInvocations()],
                    width: 6,
                }),
                new GraphWidget({
                    title: 'Errors',
                    left: [this.function.metricErrors()],
                    width: 6,
                }),
                new GraphWidget({
                    title: 'Duration',
                    left: [this.function.metricDuration()],
                    width: 6,
                }),
                new GraphWidget({
                    title: 'Throttles',
                    left: [this.function.metricThrottles()],
                    width: 6,
                })
            );
        }
    }

    private createCodeSigningConfig() {
        const signingProfile = new SigningProfile(this, 'SigningProfile', {
            platform: Platform.AWS_LAMBDA_SHA384_ECDSA,
        });

        return new CodeSigningConfig(this, 'CodeSigningConfig', {
            signingProfiles: [signingProfile],
        });
    }

    createDependencyLayer(projectName: string, functionName: string): LayerVersion {
        const requirementsFile = path.resolve(
            __dirname,
            this.LAMBDA_RELATIVE_PATH,
            `requirements.${functionName}.txt`
        );
        if (fs.existsSync(requirementsFile)) {
            return this.createAppSpecificDependencyLayer(
                functionName,
                requirementsFile,
                projectName
            );
        } else {
            return getPythonCommonDependencyLayer(this);
        }
    }

    private createAppSpecificDependencyLayer(
        functionName: string,
        requirementsFile: string,
        projectName: string
    ) {
        const outputDir = `../.build/${functionName}`;
        const pipeInstallCmd = `pip install -r ${requirementsFile} -t ${outputDir}/python`;
        try {
            child_process.execSync(pipeInstallCmd, { shell: 'False' });
        } catch (error) {
            Annotations.of(this).addError('Error installing python dependencies abort');
        }
        const code = Code.fromAsset(outputDir);
        const layerID = `${projectName}-${functionName}-dependencies`;
        return new LayerVersion(this, layerID, {
            code: code,
            compatibleRuntimes: [DEFAULT_PYTHON_VERSION],
            license: 'Apache-2.0',
            layerVersionName: `${functionName}-layer`,
            description: 'A layer to load the python dependencies',
        });
    }
}
