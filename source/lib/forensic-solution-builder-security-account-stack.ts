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

import { Construct } from 'constructs';
import { Stack, StackProps } from 'aws-cdk-lib';
import { IVpc, Vpc } from 'aws-cdk-lib/aws-ec2';
import { AWSBaseInfraConstruct, BaseInfraProps } from './infra-utils/aws-baseinfra-stack';
import { ForensicsSecurityHubConfigConstruct } from './security-hub/security-hub-construct';

export interface AwsForensicsSecHubSolutionStackProps extends StackProps {
    readonly description: string;
    readonly solutionId: string;
    readonly solutionTradeMarkName: string;
    readonly solutionProvider: string;
    readonly solutionName: string;
    readonly solutionVersion: string;
    readonly stackPrefix: string;
}

/**
 * Forensics solutions constructs stack
 */
export class ForensicsSecHubSolutionsConstructsStack extends Stack {
    public vpc: IVpc;

    constructor(
        scope: Construct,
        id: string,
        props?: AwsForensicsSecHubSolutionStackProps
    ) {
        super(scope, id, props);

        const vpcConfigDetails = this.node.tryGetContext('vpcConfigDetails');
        const subnetGroupName = this.node.tryGetContext('subnetGroupName') || 'service';

        if (
            vpcConfigDetails &&
            (vpcConfigDetails.isExistingVPC as boolean) &&
            vpcConfigDetails.vpcID
        ) {
            const vpcID = vpcConfigDetails.vpcID;

            this.vpc = Vpc.fromLookup(this, 'vpc', {
                vpcId: vpcID,
            });
        } else {
            const vpcInfo = this.node.tryGetContext('vpcInfo');
            const baseinfra = new AWSBaseInfraConstruct(
                this,
                'forensicInfra',
                vpcInfo as BaseInfraProps
            );
            this.vpc = baseinfra.vpc;
        }

        new ForensicsSecurityHubConfigConstruct(this, 'ForensicSecurityHubConstruct', {
            subnetGroupName: subnetGroupName,
            vpc: this.vpc,
        });
    }
}
