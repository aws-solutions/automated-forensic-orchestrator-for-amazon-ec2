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
import * as lambda from 'aws-cdk-lib/aws-lambda';

import { CustomResource, Duration } from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as path from 'path';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { CfnFunction } from 'aws-cdk-lib/aws-lambda';

export interface SolutionMetricsCollectorConstructProps {
    solutionDisplayName: string;
    solutionId: string;
    metricEndpoint?: string;
    version: string;
    sendAnonymousMetric: 'Yes' | 'No';
    metricsData: { [key: string]: unknown };
}

export class SolutionMetricsCollectorConstruct extends Construct {
    constructor(
        scope: Construct,
        id: string,
        props: SolutionMetricsCollectorConstructProps
    ) {
        super(scope, id);

        const metricsCollectorLambda = new lambda.Function(
            this,
            'MetricsCollectorFunction',
            {
                description: `${props.solutionDisplayName} (${props.version}): metrics collection function`,
                runtime: lambda.Runtime.NODEJS_14_X,
                code: lambda.Code.fromAsset(
                    path.resolve(__dirname, '../../lib/lambda/dist/lambda')
                ),
                handler: 'metricsCollector.lambdaHandler',
                timeout: Duration.minutes(1),
                memorySize: 128,
                environment: {
                    SOLUTION_ID: props.solutionId,
                    SOLUTION_VERSION: props.version,
                    SOLUTION_METRIC_ENDPOINT:
                        props.metricEndpoint ??
                        'https://metrics.awssolutionsbuilder.com/generic',
                },
            }
        );

        (metricsCollectorLambda.node.defaultChild as CfnFunction).cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [
                    {
                        id: 'W89',
                        reason: 'Can not change, this is CDK feature without any configuration for VPC',
                    },
                    {
                        id: 'W92',
                        reason: 'Can not change, this is CDK feature without any configuration ReservedConcurrentExecutions',
                    },
                    {
                        id: 'W58',
                        reason: 'All Lambda functions have write access to cloudwatch logs - false positive!',
                    },
                ],
            },
        };

        const metricsCollectorCrProvider = new cr.Provider(
            this,
            'metricsCollectorCrProvider',
            {
                onEventHandler: metricsCollectorLambda,
                logRetention: logs.RetentionDays.ONE_DAY,
            }
        );

        new CustomResource(this, id, {
            serviceToken: metricsCollectorCrProvider.serviceToken,
            properties: {
                sendAnonymousMetric: props.sendAnonymousMetric,
                ...props.metricsData,
            },
        });
    }
}
