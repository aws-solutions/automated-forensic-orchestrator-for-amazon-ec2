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
} from '../lib/infra-utils/infra-types';
import { CfnNagCustomResourceSuppressionAspect } from '../lib/infra-utils/cfn-nag-suppression';

const stackPrefix = 'Forensics-'.concat(ENV_NAME);
const accountId = Aws.ACCOUNT_ID;
const region = Aws.REGION;

const app = new App();

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
    Aspects.of(app).add(new AwsSolutionsChecks());
    NagSuppressions.addStackSuppressions(forensicsSolutionsStack, [
        {
            id: 'AwsSolutions-IAM5',
            reason: 'Uses service role - AWSLambdaVPCAccessExecutionRole and AWSLambdaBasicExecutionRole, Xray requires * permission, Allow key data access',
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
    if (!ec2ForensicImage) {
        Annotations.of(app).addError(
            'Configuration forensicImage AMI ID is mandatory.  The investigation will fail'
        );
    }
    Tags.of(forensicsSolutionsStack).add('Solution-id', SOLUTION_ID);
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

    Tags.of(forensicSecHubStack).add('Solution-id', SOLUTION_ID);
}
