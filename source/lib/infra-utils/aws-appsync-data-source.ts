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

import { Construct } from 'constructs';
import { CfnDataSource, CfnResolver } from 'aws-cdk-lib/aws-appsync';
import * as path from 'path';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { Table } from 'aws-cdk-lib/aws-dynamodb';
import { readFileSync } from 'fs';
import { CfnResource } from 'aws-cdk-lib';

export enum AppSyncDataSource {
    NONE = 'NONE',
    AMAZON_DYNAMODB = 'AMAZON_DYNAMODB',
    AWS_LAMBDA = 'AWS_LAMBDA',
}

export interface AppSyncDataSourceProps {
    readonly type: AppSyncDataSource;
    readonly dynamoDbConfig?: CfnDataSource.DynamoDBConfigProperty;
    readonly lambdaConfig?: CfnDataSource.LambdaConfigProperty;
}

export interface AppSyncDataSourceConstructProps {
    readonly apiId: string;
    readonly name?: string;
    readonly description?: string;
}

export interface ResolverProps {
    readonly typeName: string;
    readonly fieldName: string;
    readonly requestMappingTemplateName: string;
    readonly responseMappingTemplateName: string;
}

/**
 * Abstract class for creating AppSync Data Sources - not to be used directly
 */
export abstract class BaseDataSource extends Construct {
    public readonly name: string;
    public readonly ds: CfnDataSource;

    protected apiId: string;
    protected serviceRole: Role;

    private readonly REQUEST_RESOLVER_RELATIVE_PATH =
        '../../api/request-mapping-templates';
    private readonly RESPONSE_RESOLVER_RELATIVE_PATH =
        '../../api/response-mapping-templates';

    constructor(
        scope: Construct,
        id: string,
        props: AppSyncDataSourceConstructProps,
        extended: AppSyncDataSourceProps
    ) {
        super(scope, id);

        // Create a role to be assumed by AppSync to interact with the data source
        this.serviceRole = new Role(this, 'ServiceRole', {
            assumedBy: new ServicePrincipal('appsync'),
        });

        const name = props.name ?? id;
        this.ds = new CfnDataSource(this, 'Resource', {
            apiId: props.apiId,
            name: name,
            description: props.description,
            serviceRoleArn: this.serviceRole?.roleArn,
            ...extended,
        });
        this.name = name;
        this.apiId = props.apiId;
    }

    /**
     * creates a new resolver for this datasource and API using the given properties
     */
    public createResolver(props: ResolverProps): CfnResolver {
        const rs = new CfnResolver(this, `${props.typeName}${props.fieldName}Resolver`, {
            apiId: this.apiId,
            dataSourceName: this.name,
            typeName: props.typeName,
            fieldName: props.fieldName,
            kind: 'UNIT',
            requestMappingTemplate: readFileSync(
                path.resolve(
                    __dirname,
                    this.REQUEST_RESOLVER_RELATIVE_PATH,
                    props.requestMappingTemplateName.concat('.vtl')
                )
            ).toString('utf-8'),
            responseMappingTemplate: readFileSync(
                path.resolve(
                    __dirname,
                    this.RESPONSE_RESOLVER_RELATIVE_PATH,
                    props.responseMappingTemplateName.concat('.vtl')
                )
            ).toString('utf-8'),
        });
        this.addDataSourceDependency(rs);
        return rs;
    }

    public addDataSourceDependency(construct: CfnResource): boolean {
        construct.addDependsOn(this.ds);
        return true;
    }
}

export type NoneDataSourceProps = AppSyncDataSourceConstructProps;

/**
 * An AppSync None data source
 */
export class NoneDataSource extends BaseDataSource {
    constructor(scope: Construct, id: string, props: NoneDataSourceProps) {
        super(scope, id, props, {
            type: AppSyncDataSource.NONE,
        });
    }
}

export interface DynamoDbDataSourceProps extends AppSyncDataSourceConstructProps {
    readonly tableName: string;
    readonly tableRegion: string;
    readonly readOnlyAccess?: boolean;
}

/**
 * An AppSync datasource backed by a DynamoDB table
 */
export class DynamoDbDataSourceConstruct extends BaseDataSource {
    constructor(scope: Construct, id: string, props: DynamoDbDataSourceProps) {
        super(scope, id, props, {
            type: AppSyncDataSource.AMAZON_DYNAMODB,
            dynamoDbConfig: {
                tableName: props.tableName,
                awsRegion: props.tableRegion,
                useCallerCredentials: false,
            },
        });

        const table = Table.fromTableName(this, 'Table', props.tableName);

        // Grant AppSync read-only table access
        this.serviceRole.addToPolicy(
            new PolicyStatement({
                resources: [table.tableArn, `${table.tableArn}/index/*`],
                actions: [
                    'dynamodb:GetItem',
                    'dynamodb:BatchGetItem',
                    'dynamodb:Scan',
                    'dynamodb:Query',
                    'dynamodb:ConditionCheckItem',
                ],
                effect: Effect.ALLOW,
            })
        );
    }
}

export interface LambdaDataSourceProps extends AppSyncDataSourceConstructProps {
    readonly lambdaFunction: IFunction;
}

/**
 * An AppSync datasource backed by a Lambda function
 */
export class LambdaDataSourceConstruct extends BaseDataSource {
    constructor(scope: Construct, id: string, props: LambdaDataSourceProps) {
        super(scope, id, props, {
            type: AppSyncDataSource.AWS_LAMBDA,
            lambdaConfig: {
                lambdaFunctionArn: props.lambdaFunction.functionArn,
            },
        });

        // Grant AppSync permission to invoke the Lambda function
        this.serviceRole.addToPolicy(
            new PolicyStatement({
                resources: [props.lambdaFunction.functionArn],
                actions: ['lambda:InvokeFunction'],
                effect: Effect.ALLOW,
            })
        );
    }
}
