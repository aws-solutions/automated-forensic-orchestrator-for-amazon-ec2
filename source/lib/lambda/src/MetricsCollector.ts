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
import {
    CloudFormationCustomResourceEvent,
    CloudFormationCustomResourceFailedResponse,
    CloudFormationCustomResourceSuccessResponse,
} from 'aws-lambda';
import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import * as moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

export interface MetricsPayloadData {
    Region: string;
    Type: string;
}

export interface MetricPayload {
    Solution: string;
    Version: string;
    UUID: string;
    TimeStamp: string;
    Data: MetricsPayloadData;
}

export interface CustomerResourceProperties {
    sendAnonymousMetric: 'Yes' | 'No';
    UUID: string;
    enabledOpa: boolean;
    importedVpc: boolean;
    crossAccount: boolean;
    privateEndpoint: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type CloudFormationCustomResourceEventResource = Record<
    string | 'ServiceToken',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    any | string
>;

const SOLUTION_BUILDERS_ENDPOINT = 'https://metrics.awssolutionsbuilder.com/generic';

export async function lambdaHandler(
    event: CloudFormationCustomResourceEvent
): Promise<
    | CloudFormationCustomResourceSuccessResponse
    | CloudFormationCustomResourceFailedResponse
> {
    console.log(`${JSON.stringify(event)}`);

    let cfnResponseStatus: 'SUCCESS' | 'FAILED' = 'SUCCESS';
    let reason = '';
    const { RequestType, ResourceProperties } = event;
    console.log('Resource properties', ResourceProperties);
    if (ResourceProperties.sendAnonymousMetric != 'Yes') {
        console.log('Sending anonymous data has been disabled. Exiting.');
    } else {
        console.log('Sending anonymous data.');

        await sendAnonymousMetric(ResourceProperties, RequestType).catch((err) => {
            console.error(
                `Error occurred at ${event.RequestType}::operational-metrics-collector`,
                err
            );

            cfnResponseStatus = 'FAILED';
            reason = err.message ?? 'Custom resource error occurred.';
        });
    }
    console.log('response status', cfnResponseStatus);

    return {
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        PhysicalResourceId: 'operational-metrics-collector-cr',
        StackId: event.StackId,
        Status: cfnResponseStatus,
        Reason: reason,
    };
}

async function sendAnonymousMetric(
    requestProperties: CloudFormationCustomResourceEventResource,
    requestType: string
): Promise<AxiosResponse> {
    const { SOLUTION_ID, AWS_REGION, SOLUTION_VERSION } = process.env;
    const uuid = requestProperties.UUID ?? uuidv4();
    console.log('request uuid', uuid);
    const payload: MetricPayload = {
        Solution: SOLUTION_ID ?? '',
        Version: SOLUTION_VERSION ?? '1.0.0',
        UUID: uuid,
        TimeStamp: moment.utc().format('YYYY-MM-DD HH:mm:ss.S'),
        Data: {
            Region: AWS_REGION ?? '',
            Type: requestType,
            ...requestProperties,
        },
    };
    console.log('payload', payload);
    const payloadStr = JSON.stringify(payload);

    const config: AxiosRequestConfig = {
        headers: {
            'content-type': 'application/json',
            'content-length': payloadStr.length,
        },
    };

    console.info('Sending anonymous metric', payloadStr);

    const response = await axios.post(SOLUTION_BUILDERS_ENDPOINT, payloadStr, config);
    console.info(
        `Anonymous metric response: ${response.statusText} (${response.status})`
    );
    return response;
}
