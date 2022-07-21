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
import { Duration, StackProps } from 'aws-cdk-lib';
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
    Wait,
    WaitTime,
} from 'aws-cdk-lib/aws-stepfunctions';
import { LambdaInvoke } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Construct } from 'constructs';
import { environmentValues } from '../../infra-utils/infra-types';

export interface InvestigationStepStackProps extends StackProps {
    investigationLogGroup: ILogGroup;
    createForensicInstanceLambda: IFunction;
    checkInstanceStatusLambda: IFunction;
    checkForensicInvestigationStatusLambda: IFunction;
    attachEBSSnapShotLambda: IFunction;
    runMemoryAnalysisLambda: IFunction;
    runForensicsCommandLambda: IFunction;
    sendNotificationLambda: IFunction;
    sendErrorNotificationLambda: IFunction;
    terminateForensicInstanceLambda: IFunction;
}

/**
 * Investigation step construct
 */
export class InvestigationStepConstruct extends Construct {
    private investigationStateMachine: IStateMachine;
    constructor(scope: Construct, id: string, props: InvestigationStepStackProps) {
        super(scope, id);

        const sendErrorNotification = new LambdaInvoke(this, 'Send Error Notification', {
            lambdaFunction: props.sendErrorNotificationLambda,
        });

        const jobFailState = new Fail(this, 'Investigation Job Failed', {
            comment: 'Investigation Failed',
        });

        const investigationFailedChain = Chain.start(
            sendErrorNotification.next(jobFailState)
        );

        const createForensicInstance = new LambdaInvoke(this, 'Start Forensic Instance', {
            lambdaFunction: props.createForensicInstanceLambda,
        });

        const terminateForensicInstance = new LambdaInvoke(
            this,
            'Terminate Forensic Instance',
            {
                lambdaFunction: props.terminateForensicInstanceLambda,
            }
        );
        terminateForensicInstance.addCatch(investigationFailedChain);

        createForensicInstance.addCatch(investigationFailedChain);

        const checkForensicStatus = new LambdaInvoke(
            this,
            'Check Forensic Investigation',
            {
                lambdaFunction: props.checkForensicInvestigationStatusLambda,
            }
        );
        checkForensicStatus.addCatch(investigationFailedChain);

        const waitState = new Wait(this, 'Wait for instance boot up', {
            time: WaitTime.duration(Duration.seconds(environmentValues.WAIT_STATE_TIME)),
        });

        const waitInvestigationState = new Wait(
            this,
            'Wait for Investigation to complete',
            {
                time: WaitTime.duration(
                    Duration.seconds(environmentValues.WAIT_STATE_TIME)
                ),
            }
        );

        const checkInstanceStatus = new LambdaInvoke(
            this,
            'Check for SSM and Instance Status',
            {
                lambdaFunction: props.checkInstanceStatusLambda,
            }
        );

        checkInstanceStatus.addCatch(investigationFailedChain);

        const isInstanceReadyforForensics = new Choice(
            this,
            'Is Instance ready for Forensics?'
        );

        const isFileOrMemoryInvestigation = new Choice(
            this,
            'Is File or Memory Forensics Investigation?'
        );

        const attachEBSSnapShot = new LambdaInvoke(this, 'Attach EBS SnapShot', {
            lambdaFunction: props.attachEBSSnapShotLambda,
        });
        attachEBSSnapShot.addCatch(investigationFailedChain);

        const runMemoryAnalysis = new LambdaInvoke(
            this,
            'Load memory dump and Run memory forensics',
            {
                lambdaFunction: props.runMemoryAnalysisLambda,
            }
        );

        runMemoryAnalysis.addCatch(investigationFailedChain);

        const runForensicsCommand = new LambdaInvoke(this, 'Run Disk forensics', {
            lambdaFunction: props.runForensicsCommandLambda,
        });
        runForensicsCommand.addCatch(investigationFailedChain);

        const sendNotification = new LambdaInvoke(this, 'Send Notification', {
            lambdaFunction: props.sendNotificationLambda,
        });

        const isForensicAnalysisCompleted = new Choice(
            this,
            'Is Forensics Analysis Completed?'
        );

        const runForensicsChain = Chain.start(
            waitInvestigationState
                .next(checkForensicStatus)
                .next(
                    isForensicAnalysisCompleted
                        .when(
                            Condition.stringEquals(
                                '$.Payload.body.forensicAnalysisComplete',
                                'SUCCESS'
                            ),
                            terminateForensicInstance.next(sendNotification)
                        )
                        .when(
                            Condition.stringEquals(
                                '$.Payload.body.forensicAnalysisComplete',
                                'IN-PROGRESS'
                            ),
                            waitInvestigationState
                        )
                        .otherwise(waitInvestigationState)
                )
        );

        const investigationChain = Chain.start(
            isFileOrMemoryInvestigation
                .when(
                    Condition.stringEquals('$.Payload.body.forensicType', 'DISK'),

                    attachEBSSnapShot.next(runForensicsCommand).next(runForensicsChain)
                )
                .when(
                    Condition.stringEquals('$.Payload.body.forensicType', 'MEMORY'),
                    runMemoryAnalysis.next(runForensicsChain)
                )
        );

        const chain = Chain.start(
            createForensicInstance
                .next(waitState)
                .next(checkInstanceStatus)
                .next(
                    isInstanceReadyforForensics
                        .when(
                            Condition.stringEquals(
                                '$.Payload.body.forensicInvestigationInstance.SSM_Status',
                                'SUCCEEDED'
                            ),

                            investigationChain
                        )
                        .when(
                            Condition.stringEquals(
                                '$.Payload.body.forensicInvestigationInstance.SSM_Status',
                                'FAILED'
                            ),
                            investigationFailedChain
                        )
                        .otherwise(waitState)
                )
        );

        this.investigationStateMachine = new StateMachine(
            this,
            'Investigation StateMachine',
            {
                definition: chain,
                stateMachineName: 'Forensic-Investigation-Function',
                tracingEnabled: true,
                logs: {
                    destination: props.investigationLogGroup,
                    level: LogLevel.ALL,
                    includeExecutionData: true,
                },
            }
        );
    }

    public getStateMachine() {
        return this.investigationStateMachine;
    }
}
