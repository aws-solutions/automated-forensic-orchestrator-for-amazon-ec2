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
import { Duration } from 'aws-cdk-lib';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { ILogGroup } from 'aws-cdk-lib/aws-logs';
import {
    Chain,
    Choice,
    Condition,
    Fail,
    IStateMachine,
    LogLevel,
    StateMachine,
    // Succeed,
    Wait,
    WaitTime,
} from 'aws-cdk-lib/aws-stepfunctions';
import {
    LambdaInvoke,
    StepFunctionsStartExecution,
} from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Construct } from 'constructs';
import { environmentValues } from '../../infra-utils/infra-types';

export interface MemoryAcquisitionConstructProps {
    sendErrorNotificationLambda: IFunction;
    memoryAcquisitionLogGroup: ILogGroup;
    runMemoryAcquisitionLambda: IFunction;
    checkMemoryAcquisitionCompletionLambda: IFunction;
    forensicsIsolationLambda: IFunction;
    investigationSM: IStateMachine;
}

/**
 * Memory acquisition construct
 */
export class MemoryAcquisitionConstruct extends Construct {
    private memoryAcquisitionSMARN: string;

    private memoryAcquisitionSM: IStateMachine;

    constructor(scope: Construct, id: string, props: MemoryAcquisitionConstructProps) {
        super(scope, id);

        const sendErrorNotification = new LambdaInvoke(
            this,
            'Send Memory Acquisition Error Notification',
            {
                lambdaFunction: props.sendErrorNotificationLambda,
            }
        );

        const jobFailState = new Fail(this, 'Memory Acquisition Job Failed', {
            comment: 'Memory Acquisition Failed',
        });

        const memoryAcquisitionFailedChain = Chain.start(
            sendErrorNotification.next(jobFailState)
        );

        const runMemoryAcquisitionStep = new LambdaInvoke(
            this,
            'Perform Memory Forensics Acquisition',
            {
                lambdaFunction: props.runMemoryAcquisitionLambda,
            }
        );

        const checkMemoryAcquisitionCompletion = new LambdaInvoke(
            this,
            'Check for Memory Forensics Acquisition to be completed',
            {
                lambdaFunction: props.checkMemoryAcquisitionCompletionLambda,
            }
        );
        checkMemoryAcquisitionCompletion.addCatch(memoryAcquisitionFailedChain);

        const isMemoryAcquisitionComplete = new Choice(
            this,
            'Is Memory Acquisition Complete'
        );

        const isForensicIsolationNeeded = new Choice(
            this,
            'Is Forensic Isolation Needed'
        );

        runMemoryAcquisitionStep.addCatch(isForensicIsolationNeeded);

        const waitState = new Wait(this, 'Wait for Memory Acquisition to be completed', {
            time: WaitTime.duration(Duration.seconds(environmentValues.WAIT_STATE_TIME)),
        });

        const investigationTask = new StepFunctionsStartExecution(
            this,
            'memoryInvestigationTask',
            {
                stateMachine: props.investigationSM,
            }
        );

        const triggerForensicsIsolation = new LambdaInvoke(
            this,
            'Trigger Forensic Isolation',
            {
                lambdaFunction: props.forensicsIsolationLambda,
            }
        );
        triggerForensicsIsolation.addCatch(memoryAcquisitionFailedChain);

        const chain = Chain.start(
            runMemoryAcquisitionStep.next(
                waitState.next(
                    checkMemoryAcquisitionCompletion.next(
                        isMemoryAcquisitionComplete
                            .when(
                                Condition.stringEquals(
                                    '$.Payload.body.isMemoryAcquisitionComplete',
                                    'TRUE'
                                ),
                                isForensicIsolationNeeded
                                    .when(
                                        Condition.or(
                                            Condition.and(
                                                Condition.isPresent('$.Error'),
                                                Condition.stringEquals(
                                                    '$.Error',
                                                    'MemoryAcquisitionError'
                                                )
                                            ),
                                            Condition.and(
                                                Condition.isPresent(
                                                    '$.Payload.body.isIsolationNeeded'
                                                ),
                                                Condition.booleanEquals(
                                                    '$.Payload.body.isIsolationNeeded',
                                                    true
                                                )
                                            )
                                        ),
                                        triggerForensicsIsolation.next(investigationTask)
                                    )
                                    .otherwise(investigationTask)
                            )
                            .when(
                                Condition.stringEquals(
                                    '$.Payload.body.isMemoryAcquisitionComplete',
                                    'FALSE'
                                ),
                                waitState
                            )
                            .otherwise(waitState)
                    )
                )
            )
        );

        this.memoryAcquisitionSM = new StateMachine(
            this,
            'Acquisition Memory StateMachine',
            {
                definition: chain,
                stateMachineName: 'Memory-Forensics-Acquisition-Function',
                tracingEnabled: true,
                logs: {
                    destination: props.memoryAcquisitionLogGroup,
                    level: LogLevel.ALL,
                    includeExecutionData: true,
                },
            }
        );

        this.memoryAcquisitionSMARN = this.memoryAcquisitionSM.stateMachineArn;
    }
    public getStateMachineArn(): string {
        return this.memoryAcquisitionSMARN;
    }

    public getStateMachine(): IStateMachine {
        return this.memoryAcquisitionSM;
    }
}
