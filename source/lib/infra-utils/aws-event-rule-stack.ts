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

import { aws_events_targets } from 'aws-cdk-lib';
import { IRule, Rule } from 'aws-cdk-lib/aws-events';
import { IStateMachine } from 'aws-cdk-lib/aws-stepfunctions';
import { Construct } from 'constructs';
/**
 * Base infra props
 */
export interface AWSEventRuleConstructProps {
    triageStepfunction: IStateMachine;
    customActionARN: string;
    // TriageOrchestratorConstruct;
}

export class AWSEventRuleConstruct extends Construct {
    public forensicRule: IRule;
    constructor(scope: Construct, id: string, props: AWSEventRuleConstructProps) {
        super(scope, id);
        const triageMachineTarget = new aws_events_targets.SfnStateMachine(
            props.triageStepfunction
        );

        this.forensicRule = new Rule(this, `ForensicDefaultProcessorRule`, {
            eventPattern: {
                source: [`aws.securityhub`],
                detailType: [`Security Hub Findings - Custom Action`],
                resources: [props.customActionARN],
            },
            targets: [triageMachineTarget],
        });
    }
}
