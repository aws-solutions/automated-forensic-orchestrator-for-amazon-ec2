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

import { Template, Capture } from 'aws-cdk-lib/assertions';
import { App, Aws } from 'aws-cdk-lib';

import securityHubSolution = require('../lib/forensic-solution-builder-security-account-stack');
import {
    ENV_NAME,
    SOLUTION_ID,
    SOLUTION_NAME,
    SOLUTION_PROVIDER,
    SOLUTION_TMN,
    SOLUTION_VERSION,
} from '../lib/infra-utils/aws-solution-environment';

/*
 * SecurityHub  snapshot test
 */
test('SecurityHub Solutions snapshot test', () => {
    const app = new App({
        context: {
            sendAnonymousMetric: 'Yes',
            deployApi: true,
            apiAllowedIps: [],
            apiNotifications: true,
            apiRateLimit: 1000,
            forensicBucketComplianceMode: true,
            forensicBucketRetentionDays: 30,
            forensicBucketAccessIamRoleNames: [],
            ssmDocumentsDir: './ssm-documents',
            vol2ProfilesBucket: '',
            ssmExecutionTimeout: '1800',
            diskSize: '512',
            forensicImageName: 'sansift',
            appForensicAliasKMS: 'forensickey',
            applicationAccounts: ['*'],
            customerManagedCMKArns: {},
            ec2ForensicImage: '',
            sandbox: true,
            toolsAMI: {
                'ap-southeast-2': { amiID: 'ami-07620139298af599e' },
                'ap-southeast-1': { amiID: 'ami-0c802847a7dd848c0' },
                'us-east-1': { amiID: 'ami-0cff7528ff583bf9a' },
                'us-east-2': { amiID: 'ami-02d1e544b84bf7502' },
                'us-west-1': { amiID: 'ami-0d9858aa3c6322f73' },
                'us-west-2': { amiID: 'ami-098e42ae54c764c35' },
                'ca-central-1': { amiID: 'ami-00f881f027a6d74a0' },
                'ap-northeast-1': { amiID: 'ami-0b7546e839d7ace12' },
            },
            imageBuilderPipelines: [
                {
                    name: 'sansift',
                    dir: './image-builder-components',
                    instanceProfileName: 'ImageBuilderInstanceProfile',
                    cfnImageRecipeName: 'sansift-image01',
                    version: '1.0.2',
                    parentImage: {
                        'ap-southeast-2': { amiID: 'ami-0b7dcd6e6fd797935' },
                        'ap-southeast-1': { amiID: 'ami-055d15d9cfddf7bd3' },
                        'us-east-1': { amiID: 'ami-04505e74c0741db8d' },
                        'us-east-2': { amiID: 'ami-0fb653ca2d3203ac1' },
                        'us-west-1': { amiID: 'ami-01f87c43e618bf8f0' },
                        'us-west-2': { amiID: 'ami-0892d3c7ee96c0bf7' },
                    },
                },
            ],
            vpcInfo: {
                vpcCidr: '10.1.0.0/16',
                maxAZs: 2,
                bastionInstance: false,
                enableVpcFlowLog: true,
                enableVPCEndpoints: true,
                subnetConfig: [
                    {
                        cidrMask: 24,
                        name: 'externalDMZ',
                        subnetType: 'Public',
                        mapPublicIpOnLaunch: false,
                    },
                    {
                        cidrMask: 24,
                        name: 'service',
                        subnetType: 'Private',
                    },
                    {
                        cidrMask: 24,
                        name: 'database',
                        subnetType: 'Isolated',
                    },
                    {
                        cidrMask: 24,
                        name: 'internalDMZ',
                        subnetType: 'Isolated',
                    },
                ],
            },
            vpcConfigDetails: {
                isExistingVPC: false,
                enableVPCEndpoints: false,
                enableVpcFlowLog: false,
            },
        },
    });
    const stackPrefix = 'SecurityHub-'.concat(ENV_NAME);
    const accountId = Aws.ACCOUNT_ID;
    const region = Aws.REGION;
    // WHEN
    const stack = new securityHubSolution.ForensicsSecHubSolutionsConstructsStack(
        app,
        'TestSecurityHubSolutionsConstructsStack',
        {
            description: `(${SOLUTION_ID}) - The AWS CDK template for deployment of the ${SOLUTION_NAME}, version: ${SOLUTION_VERSION}`,
            solutionId: SOLUTION_ID,
            solutionTradeMarkName: SOLUTION_TMN,
            solutionProvider: SOLUTION_PROVIDER,
            solutionName: SOLUTION_NAME,
            solutionVersion: SOLUTION_VERSION,
            stackPrefix: stackPrefix,
            env: {
                account: app.node.tryGetContext('account') || accountId,
                region: app.node.tryGetContext('region') || region,
            },
        }
    );
    const template = Template.fromStack(stack);

    const runtimeCapture = new Capture();

    template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: runtimeCapture,
    });

    expect(runtimeCapture.asString()).toEqual('python3.9');
});
