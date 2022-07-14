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

import { IUserPool } from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';
import { CfnGraphQLApi, CfnGraphQLSchema } from 'aws-cdk-lib/aws-appsync';
import * as path from 'path';
import { ManagedPolicy, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Asset } from 'aws-cdk-lib/aws-s3-assets';
import { CfnResource } from 'aws-cdk-lib';

export enum AuthorizationType {
    IAM = 'AWS_IAM',
    USER_POOL = 'AMAZON_COGNITO_USER_POOLS',
    OIDC = 'OPENID_CONNECT',
}

export interface AuthorizationMode {
    readonly authorizationType: AuthorizationType;
    readonly userPoolConfig?: UserPoolConfig;
    readonly openIdConnectConfig?: OpenIdConnectConfig;
}

export enum UserPoolDefaultAction {
    ALLOW = 'ALLOW',
    DENY = 'DENY',
}

export interface UserPoolConfig {
    readonly userPool: IUserPool;
    readonly appIdClientRegex?: string;
    readonly defaultAction?: UserPoolDefaultAction;
}

export interface OpenIdConnectConfig {
    readonly tokenExpiryFromAuth?: number;
    readonly tokenExpiryFromIssue?: number;
    readonly clientId?: string;
    readonly oidcProvider: string;
}

export interface AuthorizationConfig {
    readonly defaultAuthorization?: AuthorizationMode;
    readonly additionalAuthorizationModes?: AuthorizationMode[];
}

export enum FieldLogLevel {
    ERROR = 'ERROR',
    ALL = 'ALL',
}

export interface LogConfig {
    readonly fieldLogLevel?: FieldLogLevel;
}

export interface DynamoDbDataSourceProps {
    readonly tableName: string;
}

export interface AWSAppSyncApiConstructProps {
    readonly name: string;
    readonly schemaPath?: string;
    readonly authorizationConfig?: AuthorizationConfig;
    readonly logConfig: LogConfig;
}

/**
 * AppSync API Construct
 * This construct creates an AppSync API and provides methods to add data sources, a schema and resolvers
 */
export class AWSAppSyncApiConstruct extends Construct {
    public readonly apiId: string;
    public readonly arn: string;
    public readonly graphqlUrl: string;
    public readonly name: string;
    public readonly modes: AuthorizationType[];
    public readonly schema: CfnGraphQLSchema;

    private readonly SCHEMA_RELATIVE_PATH = '../../api';
    private readonly api: CfnGraphQLApi;

    constructor(scope: Construct, id: string, props: AWSAppSyncApiConstructProps) {
        super(scope, id);

        const schemaPath =
            props.schemaPath ??
            path.resolve(__dirname, this.SCHEMA_RELATIVE_PATH, 'forensics-api.gql');

        const defaultMode = props.authorizationConfig?.defaultAuthorization ?? {
            authorizationType: AuthorizationType.IAM,
        };
        const additionalModes =
            props.authorizationConfig?.additionalAuthorizationModes ?? [];
        const modes = [defaultMode, ...additionalModes];

        this.modes = modes.map((mode) => mode.authorizationType);

        // Create forensics API
        this.api = new CfnGraphQLApi(this, 'API', {
            name: props.name,
            authenticationType: defaultMode.authorizationType,
            logConfig: this.setupLogConfig(props.logConfig),
            openIdConnectConfig: this.setupOpenIdConnectConfig(
                defaultMode.openIdConnectConfig
            ),
            userPoolConfig: this.setupUserPoolConfig(defaultMode.userPoolConfig),
            additionalAuthenticationProviders:
                this.setupAdditionalAuthorizationModes(additionalModes),
            xrayEnabled: true,
        });

        this.apiId = this.api.attrApiId;
        this.arn = this.api.attrArn;
        this.graphqlUrl = this.api.attrGraphQlUrl;
        this.name = this.api.name;

        // Add a schema to the API
        this.schema = new CfnGraphQLSchema(this, 'Schema', {
            apiId: this.api.attrApiId,
            definitionS3Location: new Asset(this, 'BundledAsset', {
                path: schemaPath,
            }).s3ObjectUrl,
        });

        this.schema.addDependsOn(this.api);
    }

    private setupLogConfig(config: LogConfig) {
        const logsRoleArn: string = new Role(this, 'ApiLogsRole', {
            assumedBy: new ServicePrincipal('appsync.amazonaws.com'),
            managedPolicies: [
                ManagedPolicy.fromAwsManagedPolicyName(
                    'service-role/AWSAppSyncPushToCloudWatchLogs'
                ),
            ],
        }).roleArn;
        return {
            cloudWatchLogsRoleArn: logsRoleArn,
            excludeVerboseContent: false,
            fieldLogLevel: config.fieldLogLevel,
        };
    }

    private setupOpenIdConnectConfig(config?: OpenIdConnectConfig) {
        if (!config) return undefined;
        return {
            authTtl: config.tokenExpiryFromAuth,
            clientId: config.clientId,
            iatTtl: config.tokenExpiryFromIssue,
            issuer: config.oidcProvider,
        };
    }

    private setupUserPoolConfig(config?: UserPoolConfig) {
        if (!config) return undefined;
        return {
            userPoolId: config.userPool.userPoolId,
            awsRegion: config.userPool.stack.region,
            appIdClientRegex: config.appIdClientRegex,
            defaultAction: config.defaultAction || UserPoolDefaultAction.ALLOW,
        };
    }

    private setupAdditionalAuthorizationModes(modes?: AuthorizationMode[]) {
        if (!modes || modes.length === 0) return undefined;
        return modes.reduce<CfnGraphQLApi.AdditionalAuthenticationProviderProperty[]>(
            (acc, mode) => [
                ...acc,
                {
                    authenticationType: mode.authorizationType,
                    userPoolConfig: this.setupUserPoolConfig(mode.userPoolConfig),
                    openIdConnectConfig: this.setupOpenIdConnectConfig(
                        mode.openIdConnectConfig
                    ),
                },
            ],
            []
        );
    }

    public addSchemaDependency(construct: CfnResource): boolean {
        construct.addDependsOn(this.schema);
        return true;
    }
}
