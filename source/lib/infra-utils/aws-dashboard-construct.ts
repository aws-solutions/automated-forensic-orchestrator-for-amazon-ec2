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
import { Dashboard, GraphWidget, TextWidget } from 'aws-cdk-lib/aws-cloudwatch';
import { IStateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { Construct } from 'constructs';

export interface StepFunctionDashBoardFnProps {
    dashboard: Dashboard;
    stateMachine: IStateMachine;
    applicationName: string;
}

/**
 * Cloudwatch dashboard construct
 * This construct creates/reuses common layer if no specific requirement spec set
 */
export class StepFunctionDashboardConstruct extends Construct {
    constructor(scope: Construct, id: string, props: StepFunctionDashBoardFnProps) {
        super(scope, id);

        props.dashboard.addWidgets(
            // Create Title for Dashboard
            new TextWidget({
                markdown: `# Dashboard ${props.applicationName} Step function`,
                height: 1,
                width: 24,
            }),
            new GraphWidget({
                title: 'Failed',
                left: [props.stateMachine.metricFailed()],
                width: 6,
            }),
            new GraphWidget({
                title: 'TimeOut',
                left: [props.stateMachine.metricTimedOut()],
                width: 6,
            }),

            new GraphWidget({
                title: 'Throttles',
                left: [props.stateMachine.metricThrottled()],
                width: 6,
            }),
            new GraphWidget({
                title: 'TimedOut',
                left: [props.stateMachine.metricTimedOut()],
                width: 6,
            })
        );
    }
}
