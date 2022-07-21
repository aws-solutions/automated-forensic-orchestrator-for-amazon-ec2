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
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import {
    Chain,
    Choice,
    Condition,
    IntegrationPattern,
    IStateMachine,
    LogLevel,
    Parallel,
    StateMachine,
    TaskInput,
} from 'aws-cdk-lib/aws-stepfunctions';
import {
    LambdaInvoke,
    SnsPublish,
    StepFunctionsStartExecution,
} from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Construct } from 'constructs';
import { DiskAcquisitionConstruct } from '../acquisition/disk-acquisition-step-functions';
import { MemoryAcquisitionConstruct } from '../acquisition/memory-acquisition-step-functions';
import { ForensicsAcquisitionConstruct } from '../../forensic-core/acquisition-functions-construct';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { ILogGroup } from 'aws-cdk-lib/aws-logs';
import { ITable } from 'aws-cdk-lib/aws-dynamodb';

/**
 * Triage orchestrator props
 */
export interface TriageOrchestratorProps {
    vpcId: string;
    forensicsAcquisitionFns: ForensicsAcquisitionConstruct;
    instanceIsolationLambda: IFunction;
    triageInstanceLambda: IFunction;
    investigationSM: IStateMachine;
    snsTopic: ITopic;
    snsDataKey: IKey;
    triageLogGroup: ILogGroup;
    sendNotificationLambda: IFunction;
    sendErrorNotificationLambda: IFunction;
    readonly forensicTable: ITable;
}

/**
 * Triage orchestrator construct
 */
export class TriageOrchestratorConstruct extends Construct {
    public triageStepfunction: StateMachine;

    public memoryAcquisitionStepfunction: IStateMachine;

    public diskAcquisitionStepfunction: IStateMachine;

    constructor(scope: Construct, id: string, props: TriageOrchestratorProps) {
        super(scope, id);

        const getInstanceInfo = new LambdaInvoke(this, 'Get Instance Info Case', {
            lambdaFunction: props.triageInstanceLambda,
        });

        const isAcquisitionNeeded = new Choice(this, 'Is Acquisition candidate');

        const acquisitionFlow = new Parallel(this, 'acquistionFlow', {});

        const diskAcquisitionConstruct = new DiskAcquisitionConstruct(
            this,
            'DiskAcquisitionConstruct',
            {
                performDiskAcquisitionSetupLambda:
                    props.forensicsAcquisitionFns.performDiskAcquisitionSetupLambda,
                performInstanceIsolationLambda:
                    props.forensicsAcquisitionFns.performInstanceIsolationLambda,
                performInstanceSnapShotLambda:
                    props.forensicsAcquisitionFns.performInstanceSnapShotLambda,
                snapShotCompletionCheckerLambda:
                    props.forensicsAcquisitionFns.snapShotCompletionCheckerLambda,
                shareSnapShotLambda: props.forensicsAcquisitionFns.shareSnapShotLambda,
                investigationSM: props.investigationSM,
                diskAcquisitionLogGroup: props.triageLogGroup,
                sendErrorNotificationLambda: props.sendErrorNotificationLambda,
                copySnapShotLambda:
                    props.forensicsAcquisitionFns.performSnapshotCopyLambda,
                copySnapShotCheckerLambda:
                    props.forensicsAcquisitionFns.snapshotCopyCheckerLambda,
            }
        );

        this.diskAcquisitionStepfunction = diskAcquisitionConstruct.getStateMachine();

        const memoryAcquisitionConstruct = new MemoryAcquisitionConstruct(
            this,
            'MemoryAcquisitionConstruct',
            {
                runMemoryAcquisitionLambda:
                    props.forensicsAcquisitionFns.runMemoryAcquisitionLambda,
                checkMemoryAcquisitionCompletionLambda:
                    props.forensicsAcquisitionFns.checkMemoryAcquisitionCompletionLambda,
                investigationSM: props.investigationSM,
                memoryAcquisitionLogGroup: props.triageLogGroup,
                forensicsIsolationLambda: props.instanceIsolationLambda,
                sendErrorNotificationLambda: props.sendErrorNotificationLambda,
            }
        );

        this.memoryAcquisitionStepfunction = memoryAcquisitionConstruct.getStateMachine();

        const diskAcquisitionTask = new StepFunctionsStartExecution(
            this,
            'diskAcquisitionTask',
            {
                stateMachine: diskAcquisitionConstruct.getStateMachine(),
                integrationPattern: IntegrationPattern.RUN_JOB,
            }
        );

        const memoryAcquisitionTask = new StepFunctionsStartExecution(
            this,
            'memoryAcquisitionTask',
            {
                stateMachine: memoryAcquisitionConstruct.getStateMachine(),
                integrationPattern: IntegrationPattern.RUN_JOB,
            }
        );

        acquisitionFlow.branch(diskAcquisitionTask).branch(memoryAcquisitionTask);

        const role = new Role(this, 'Role', {
            assumedBy: new ServicePrincipal('states.amazonaws.com'),
        });
        role.addToPolicy(
            new PolicyStatement({
                resources: [props.snsTopic.topicArn],
                actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                effect: Effect.ALLOW,
            })
        );

        const publishMessage = new SnsPublish(this, 'Publish message', {
            topic: props.snsTopic,
            message: TaskInput.fromText(
                `Forensic Triage details are recorded in table ${props.forensicTable.tableName}`
            ),
            resultPath: '$',
            subject: `Forensic Triage completed`,
        });

        const chain = Chain.start(getInstanceInfo).next(
            isAcquisitionNeeded
                .when(
                    Condition.booleanEquals('$.Payload.body.isAcquisitionRequired', true),
                    acquisitionFlow.next(publishMessage)
                )
                .otherwise(publishMessage)
        );

        this.triageStepfunction = new StateMachine(this, 'ForensicsTriageStateMachine', {
            definition: chain,
            stateMachineName: 'Forensic-Triage-Function',
            tracingEnabled: true,
            logs: {
                destination: props.triageLogGroup,
                level: LogLevel.ALL,
                includeExecutionData: true,
            },
        });

        this.triageStepfunction.grantTaskResponse(role);

        this.triageStepfunction.addToRolePolicy(
            new PolicyStatement({
                resources: [props.snsTopic.topicArn],
                actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                effect: Effect.ALLOW,
            })
        );
        this.triageStepfunction.addToRolePolicy(
            new PolicyStatement({
                resources: [props.snsDataKey.keyArn],
                actions: ['kms:GenerateDataKey*', 'kms:Decrypt', 'kms:Get*'],
                effect: Effect.ALLOW,
            })
        );
        props.snsDataKey.grantEncryptDecrypt(this.triageStepfunction);

        props.snsTopic.grantPublish(this.triageStepfunction);
    }
}
