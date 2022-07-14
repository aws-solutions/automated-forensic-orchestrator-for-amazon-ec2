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
    Wait,
    WaitTime,
    TaskInput,
    JsonPath,
} from 'aws-cdk-lib/aws-stepfunctions';
import {
    LambdaInvoke,
    StepFunctionsStartExecution,
} from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Construct } from 'constructs';
import { environmentValues } from '../../infra-utils/infra-types';

export interface DiskAcquisitionConstructProps {
    copySnapShotLambda: IFunction;
    copySnapShotCheckerLambda: IFunction;
    sendErrorNotificationLambda: IFunction;
    diskAcquisitionLogGroup: ILogGroup;
    performDiskAcquisitionSetupLambda: IFunction;
    performInstanceIsolationLambda: IFunction;
    performInstanceSnapShotLambda: IFunction;
    snapShotCompletionCheckerLambda: IFunction;
    shareSnapShotLambda: IFunction;
    investigationSM: IStateMachine;
}

/**
 * Disk acquisition construct
 */
export class DiskAcquisitionConstruct extends Construct {
    private stateMachineARN: string;

    private diskAcquisitionStateMachine: IStateMachine;

    constructor(scope: Construct, id: string, props: DiskAcquisitionConstructProps) {
        super(scope, id);

        const performDiskAcquisitionSetup = new LambdaInvoke(
            this,
            'Perform Disk Forensics Acquisition Set up',
            {
                lambdaFunction: props.performDiskAcquisitionSetupLambda,
                inputPath: '$',
                payload: TaskInput.fromObject({
                    input: JsonPath.stringAt('$'),
                    sfn: JsonPath.stringAt('$$.Execution'),
                }),
            }
        );

        const sendErrorNotification = new LambdaInvoke(
            this,
            'Send Disk Acquisition Error Notification',
            {
                lambdaFunction: props.sendErrorNotificationLambda,
            }
        );

        const jobFailState = new Fail(this, 'Disk Acquisition Job Failed', {
            comment: 'Disk Acquisition Failed',
        });

        const diskAcquisitionFailedChain = Chain.start(
            sendErrorNotification.next(jobFailState)
        );

        const performInstanceSnapshot = new LambdaInvoke(
            this,
            'Perform Instance Snapshot',
            {
                lambdaFunction: props.performInstanceSnapShotLambda,
            }
        );
        performInstanceSnapshot.addCatch(diskAcquisitionFailedChain);

        const isSnapshotCompletefn = new LambdaInvoke(
            this,
            'Check for Instance Snapshot Completion',
            {
                lambdaFunction: props.snapShotCompletionCheckerLambda,
            }
        );
        isSnapshotCompletefn.addCatch(diskAcquisitionFailedChain);

        const isAppCopySnapshotCompletefn = new LambdaInvoke(
            this,
            'Check for Application Account Copy Snapshot Completion',
            {
                lambdaFunction: props.copySnapShotCheckerLambda,
            }
        );
        isAppCopySnapshotCompletefn.addCatch(diskAcquisitionFailedChain);

        const appCopySnapshotfn = new LambdaInvoke(
            this,
            'Application Copy Instance Snapshot',
            {
                lambdaFunction: props.copySnapShotLambda,
            }
        );
        appCopySnapshotfn.addCatch(diskAcquisitionFailedChain);

        const isAppCopySnapshotComplete = new Choice(
            this,
            'Is Application Copy SnapShot Complete'
        );
        const waitAppCopySnapShotState = new Wait(
            this,
            'Wait for Application Copy Snapshot to be completed',
            {
                time: WaitTime.duration(
                    Duration.seconds(environmentValues.WAIT_STATE_TIME)
                ),
            }
        );

        const shareSnapshotfn = new LambdaInvoke(this, 'Share Instance Snapshot', {
            lambdaFunction: props.shareSnapShotLambda,
        });

        shareSnapshotfn.addCatch(diskAcquisitionFailedChain);

        const isCopySnapshotCompletefn = new LambdaInvoke(
            this,
            'Check for Copy Snapshot Completion',
            {
                lambdaFunction: props.copySnapShotCheckerLambda,
            }
        );
        isCopySnapshotCompletefn.addCatch(diskAcquisitionFailedChain);

        const copySnapshotfn = new LambdaInvoke(this, 'Copy Instance Snapshot', {
            lambdaFunction: props.copySnapShotLambda,
        });
        copySnapshotfn.addCatch(diskAcquisitionFailedChain);

        const isCopySnapShotComplete = new Choice(this, 'Is Copy SnapShot Complete');
        const waitCopySnapShotState = new Wait(
            this,
            'Wait for Copy Snapshot to be completed',
            {
                time: WaitTime.duration(
                    Duration.seconds(environmentValues.WAIT_STATE_TIME)
                ),
            }
        );

        const waitState = new Wait(this, 'Wait for Snapshot to be completed', {
            time: WaitTime.duration(Duration.seconds(environmentValues.WAIT_STATE_TIME)),
        });

        const isSnapShotComplete = new Choice(this, 'Is SnapShot Complete');

        const investigationTask = new StepFunctionsStartExecution(
            this,
            'diskInvestigationTask',
            {
                stateMachine: props.investigationSM,
            }
        );

        const snapshotCopyToForensicChain = Chain.start(
            copySnapshotfn
                .next(waitCopySnapShotState)
                .next(isCopySnapshotCompletefn)
                .next(
                    isCopySnapShotComplete
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isSnapShotCopyComplete',
                                true
                            ),
                            investigationTask
                        )
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isSnapShotCopyComplete',
                                false
                            ),
                            waitCopySnapShotState
                        )
                        .otherwise(waitCopySnapShotState)
                )
        );

        const triggerCopySnapshotFlow = Chain.start(
            shareSnapshotfn.next(snapshotCopyToForensicChain)
        );

        const appSnapshotCopyChain = Chain.start(
            appCopySnapshotfn
                .next(waitAppCopySnapShotState)
                .next(isAppCopySnapshotCompletefn)
                .next(
                    isAppCopySnapshotComplete
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isAppCopySnapShotComplete',
                                true
                            ),
                            triggerCopySnapshotFlow
                        )
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isAppCopySnapShotComplete',
                                false
                            ),
                            waitAppCopySnapShotState
                        )
                        .otherwise(waitAppCopySnapShotState)
                )
        );

        const snapshotCompletionChain = Chain.start(
            performInstanceSnapshot
                .next(waitState)
                .next(isSnapshotCompletefn)
                .next(
                    isSnapShotComplete
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isSnapShotComplete',
                                true
                            ),
                            appSnapshotCopyChain
                        )
                        .when(
                            Condition.booleanEquals(
                                '$.Payload.body.isSnapShotComplete',
                                false
                            ),
                            waitState
                        )
                        .otherwise(waitState)
                )
        );

        const chain = Chain.start(
            performDiskAcquisitionSetup.next(snapshotCompletionChain)
        );

        this.diskAcquisitionStateMachine = new StateMachine(
            this,
            'Acquisition Disk StateMachine',
            {
                definition: chain,
                stateMachineName: 'Disk-Forensics-Acquisition-Function',
                tracingEnabled: true,
                logs: {
                    destination: props.diskAcquisitionLogGroup,
                    level: LogLevel.ALL,
                    includeExecutionData: true,
                },
            }
        );
        this.stateMachineARN = this.diskAcquisitionStateMachine.stateMachineArn;
    }
    getStateMachineArn(): string {
        return this.stateMachineARN;
    }

    getStateMachine(): IStateMachine {
        return this.diskAcquisitionStateMachine;
    }
}
