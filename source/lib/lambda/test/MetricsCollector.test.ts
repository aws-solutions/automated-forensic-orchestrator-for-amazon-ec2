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
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import axios from 'axios';
import { lambdaHandler } from '../src/MetricsCollector';

import { CloudFormationCustomResourceEvent } from 'aws-lambda';

jest.mock('axios');
const mockTimeStamp = new Date();
export const consoleInfoSpy = jest.spyOn(console, 'info');

export const consoleErrorSpy = jest.spyOn(console, 'error');

export const mockISOTimeStamp = mockTimeStamp.toISOString();

jest.mock('moment', () => {
    const originalMoment = jest.requireActual('moment');
    const mockMoment = (_date: string | undefined) => originalMoment(mockTimeStamp);
    mockMoment.utc = () => ({
        format: () => mockISOTimeStamp,
    });
    return mockMoment;
});

describe('Send anonymous metrics test', () => {
    // Mock event data
    const event: CloudFormationCustomResourceEvent = {
        RequestType: 'Update',
        ServiceToken:
            'arn:aws:lambda:ap-southeast-2:123:function:FirewallObjectExtensionSo-metricscollectorconstruc-SPlsyZxT4L4G',
        ResponseURL:
            'https://cloudformation-custom-resource-response-apsoutheast2.s3-ap-southeast-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aap-southeast-2%3A123%3Astack/FirewallObjectExtensionSolutionStack/64116200-4f0e-11ec-9b4b-02366ddaec5c%7Cmetricscollectorconstruct906DBEA5%7C04f12ab5-0f67-4f5c-b0e4-26c60f0995af?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20220124T062057Z&X-Amz-SignedHeaders=host&X-Amz-Expires=7199&X-Amz-Credential=AKIA6MM33IIZ6T5O5L5N%2F20220124%2Fap-southeast-2%2Fs3%2Faws4_request&X-Amz-Signature=662c06118370f3951aa5b684a5959a62fe2572b19d182f78d94e43753b5f744f',
        StackId: 'mock-stack-id',
        RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
        LogicalResourceId: 'metricscollectorconstruct906DBEA5',
        PhysicalResourceId: 'operational-metrics-collector-cr',
        ResourceType: 'AWS::CloudFormation::CustomResource',
        ResourceProperties: {
            ServiceToken:
                'arn:aws:lambda:ap-southeast-2:123:function:FirewallObjectExtensionSo-metricscollectorconstruc-SPlsyZxT4L4G',
            enabledOpa: 'false',
            sendAnonymousMetric: 'Yes',
            importedVpc: 'false',
            privateEndpoint: 'false',
        },
        OldResourceProperties: {
            ServiceToken:
                'arn:aws:lambda:ap-southeast-2:123:function:FirewallObjectExtensionSo-metricscollectorconstruc-SPlsyZxT4L4G',
            enabledOpa: 'false',
            importedVpc: 'false',
            privateEndpoint: 'false',
        },
    };
    const OLD_ENV = process.env;
    beforeEach(() => {
        process.env = { ...OLD_ENV };
        jest.resetAllMocks();
    });

    afterEach(() => {
        process.env = OLD_ENV;
        jest.clearAllMocks();
    });
    test('Should use UUID from cfn is present', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockResolvedValue({ status: 200, statusText: 'OK' });
        event.ResourceProperties.UUID = 'uuid-1';
        const result = await lambdaHandler(event);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const sentBody = (axios.post as any).mock.calls[0][1];

        expect(JSON.parse(sentBody).UUID).toBe('uuid-1');
        expect(result).toEqual({
            Status: 'SUCCESS',
            LogicalResourceId: 'metricscollectorconstruct906DBEA5',
            PhysicalResourceId: 'operational-metrics-collector-cr',
            Reason: '',
            RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
            StackId: 'mock-stack-id',
        });
    });

    test('Should generate UUID when UUID from cfn is abpresent', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockResolvedValue({ status: 200, statusText: 'OK' });
        event.ResourceProperties.UUID = undefined;
        const result = await lambdaHandler(event);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const sentBody = (axios.post as any).mock.calls[0][1];

        expect(JSON.parse(sentBody).UUID).toBeDefined();
        expect(result).toEqual({
            Status: 'SUCCESS',
            LogicalResourceId: 'metricscollectorconstruct906DBEA5',
            PhysicalResourceId: 'operational-metrics-collector-cr',
            Reason: '',
            RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
            StackId: 'mock-stack-id',
        });
    });

    test('Should return success when sending anonymous metric succeeds', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockResolvedValue({ status: 200, statusText: 'OK' });

        const result = await lambdaHandler(event);

        expect(result).toEqual({
            Status: 'SUCCESS',
            LogicalResourceId: 'metricscollectorconstruct906DBEA5',
            PhysicalResourceId: 'operational-metrics-collector-cr',
            Reason: '',
            RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
            StackId: 'mock-stack-id',
        });
    });

    test('Should return success when unable to send anonymous usage', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockRejectedValue({ status: 500, statusText: 'FAILS' });

        const result = await lambdaHandler(event);

        expect(result).toMatchObject({
            Status: 'FAILED',
            LogicalResourceId: 'metricscollectorconstruct906DBEA5',
            PhysicalResourceId: 'operational-metrics-collector-cr',
            Reason: 'Custom resource error occurred.',
            RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
            StackId: 'mock-stack-id',
        });
    });

    test('Should return success when unable to send anonymous usage with preconfigured value', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockRejectedValue({ status: 500, statusText: 'FAILS' });
        process.env.SOLUTION_ID = 'solution-id-1';
        process.env.AWS_REGION = 'mock-region-2';
        process.env.SOLUTION_VERSION = '2.0.0';
        const result = await lambdaHandler(event);

        expect(result).toMatchObject({
            Status: 'FAILED',
            LogicalResourceId: 'metricscollectorconstruct906DBEA5',
            PhysicalResourceId: 'operational-metrics-collector-cr',
            Reason: 'Custom resource error occurred.',
            RequestId: '04f12ab5-0f67-4f5c-b0e4-26c60f0995af',
            StackId: 'mock-stack-id',
        });
    });

    test('Should return success when sending anonymous metric without data', async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axios.post as any).mockResolvedValue({ status: 200, statusText: 'OK' });
        const emptyDataPayload = { ...event };

        emptyDataPayload.ResourceProperties = {
            ServiceToken: emptyDataPayload.ResourceProperties.ServiceToken,
        };

        const result = await lambdaHandler(emptyDataPayload);

        expect(result.Status).toBe('SUCCESS');
    });

    test('Should not send antonymous metric when sendAnonymousMetric is "No"', async () => {
        event.ResourceProperties.sendAnonymousMetric = 'No';

        const result = await lambdaHandler(event);

        expect(result.Status).toBe('SUCCESS');
    });
});
