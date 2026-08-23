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

import { Template } from 'aws-cdk-lib/assertions';
import { App, Stack } from 'aws-cdk-lib';

import { ForensicSSMDBuilderConstruct } from '../lib/forensic-ssm-document-builder-stack';

const buildTemplate = (): Template => {
    const app = new App({
        context: {
            ssmDocumentsDir: './ssm-documents',
            ssmExecutionTimeout: '1800',
        },
    });
    const stack = new Stack(app, 'SsmDocumentStack', {
        env: { account: '123456789012', region: 'us-east-1' },
    });

    new ForensicSSMDBuilderConstruct(stack, 'ssmDocuments', {});

    return Template.fromStack(stack);
};

describe('ForensicSSMDBuilderConstruct', () => {
    test('creates one Command document per file in ssm-documents', () => {
        const template = buildTemplate();

        const documents = template.findResources('AWS::SSM::Document');
        expect(Object.keys(documents).length).toBeGreaterThan(0);
        Object.values(documents).forEach((document) => {
            expect(document.Properties.DocumentType).toEqual('Command');
        });
    });

    // CloudFormation defaults a Content change to UpdateMethod: Replace, which is
    // DeleteDocument then CreateDocument. The memory acquisition documents are shared
    // cross-account at run time and only un-shared on the success path, and SSM refuses to
    // delete a shared document, so Replace turns a content change into UPDATE_ROLLBACK for
    // any operator whose last acquisition failed. NewVersion never deletes.
    test('updates every document by version instead of replacing it', () => {
        const template = buildTemplate();

        const documents = template.findResources('AWS::SSM::Document');
        Object.entries(documents).forEach(([logicalId, document]) => {
            expect({ logicalId, updateMethod: document.Properties.UpdateMethod }).toEqual(
                {
                    logicalId,
                    updateMethod: 'NewVersion',
                }
            );
        });
    });
});
