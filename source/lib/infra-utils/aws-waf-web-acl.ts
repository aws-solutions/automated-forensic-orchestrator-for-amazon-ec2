/* eslint-disable no-mixed-spaces-and-tabs */
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
import { IResolvable } from 'aws-cdk-lib';
import { CfnIPSet, CfnWebACL } from 'aws-cdk-lib/aws-wafv2';

export enum WAFScope {
    CLOUDFRONT = 'CLOUDFRONT',
    REGIONAL = 'REGIONAL',
}

export interface AWSWafWebACLProps {
    name: string;
    /** Specify if must be a Cloudfront or a Regional WAF */
    wafScope?: WAFScope;
    /** Maximum number of calls from the same IP in a 5 minutes period
     * @default no limits
     */
    rateLimit?: number;
    /** WAF WebACLs request sampling
     */
    sampleRequestsEnabled: boolean;
    /** List of IPs to allow access from
     */
    allowList: string[];
    /** Add AWS Managed rules:
     * - **AWS-AWSManagedRulesAmazonIpReputationList**
     * - **AWS-AWSManagedRulesCommonRuleSet**
     * - **AWS-AWSManagedRulesKnownBadInputsRuleSet**
     *
     * @default no rules
     */
    enableManagedRules?: boolean;
    /** Rules to exclude from the Core rule set (CRS)
     * https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
     * @default no excluded rules
     */
    excludedManagedRules?: string[];
    /** Adds a custom rule which checks HTTP body against the specified body size
     * Adds the CRS SizeRestrictions_BODY rule to excludedManagedRules
     * @default no excluded rules
     */
    customBodySize?: number;
    /** Custom response bodies
     * @default no custom response bodies
     */
    customResponseBodies?: {
        [key: string]: IResolvable | CfnWebACL.CustomResponseBodyProperty;
    };
    /** Custom response body to apply for all rules
     *
     * @default no custom response body
     */
    customResponseBody?: IResolvable | CfnWebACL.CustomResponseProperty;
    /** Add GQL Custom Rules:
     * - **PreventIntrospection**
     *
     * @default no rules
     */
    enableGqlCustomRules?: boolean;
}

export class AWSWafWebACL extends Construct {
    webAcl: CfnWebACL;

    constructor(scope: Construct, id: string, props: AWSWafWebACLProps) {
        super(scope, id);

        // default
        if (!props.wafScope) props.wafScope = WAFScope.CLOUDFRONT;
        const rules = [];

        if (props.customBodySize) {
            //Add SizeRestrictions_BODY in to set
            const excludedManagedRules = new Set(props.excludedManagedRules).add(
                'SizeRestrictions_BODY'
            );
            // convert set to array
            props.excludedManagedRules = [...excludedManagedRules];
        }

        //rate based rules
        if (props.rateLimit) {
            // limit the calls to a MAX in a 5 mintues period
            const rateLimitRule: CfnWebACL.RuleProperty = {
                name: 'RateLimit',
                priority: 0,
                statement: {
                    rateBasedStatement: {
                        limit: props.rateLimit,
                        aggregateKeyType: 'IP',
                    },
                },
                action: {
                    block: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}-RateLimit`,
                },
            };
            rules.push(rateLimitRule);
        }

        if (props.enableManagedRules) {
            const reputationListRule: CfnWebACL.RuleProperty = {
                name: 'AWS-AWSManagedRulesAmazonIpReputationList',
                priority: 1,
                statement: {
                    managedRuleGroupStatement: {
                        vendorName: 'AWS',
                        name: 'AWSManagedRulesAmazonIpReputationList',
                    },
                },
                overrideAction: {
                    none: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}-AWSManagedRulesAmazonIpReputationList`,
                },
            };

            // covers xss
            const commonSetRule: CfnWebACL.RuleProperty = {
                name: 'AWS-AWSManagedRulesCommonRuleSet',
                priority: 2,
                statement: {
                    managedRuleGroupStatement: {
                        vendorName: 'AWS',
                        name: 'AWSManagedRulesCommonRuleSet',
                        ...(props.excludedManagedRules && {
                            excludedRules: props.excludedManagedRules?.map((r) => ({
                                name: r,
                            })),
                        }),
                    },
                },
                overrideAction: {
                    none: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}-AWSManagedRulesCommonRuleSet`,
                },
            };

            const knownBadInputRule: CfnWebACL.RuleProperty = {
                name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
                priority: 3,
                statement: {
                    managedRuleGroupStatement: {
                        vendorName: 'AWS',
                        name: 'AWSManagedRulesKnownBadInputsRuleSet',
                    },
                },
                overrideAction: {
                    none: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}-AWSManagedRulesKnownBadInputsRuleSet`,
                },
            };

            rules.push(reputationListRule);
            rules.push(commonSetRule);
            rules.push(knownBadInputRule);
        }

        //custom body size
        if (props.customBodySize) {
            const customBodySize: CfnWebACL.RuleProperty = {
                name: `${props.name}-CustomBodySize`,
                priority: 4,
                statement: {
                    sizeConstraintStatement: {
                        fieldToMatch: {
                            body: {},
                        },
                        comparisonOperator: 'GT',
                        size: props.customBodySize,
                        textTransformations: [
                            {
                                type: 'NONE',
                                priority: 0,
                            },
                        ],
                    },
                },
                action: {
                    block: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}CustomBodySize`,
                },
            };
            rules.push(customBodySize);
        }

        // prevent GraphQL introspection
        if (props.enableGqlCustomRules) {
            const gqlPreventIntrospection: CfnWebACL.RuleProperty = {
                name: `${props.name}-PreventIntrospection`,
                priority: 5,
                statement: {
                    byteMatchStatement: {
                        fieldToMatch: {
                            body: {},
                        },
                        positionalConstraint: 'CONTAINS',
                        searchString: '__schema',
                        textTransformations: [
                            {
                                type: 'NONE',
                                priority: 0,
                            },
                        ],
                    },
                },
                action: {
                    block: {},
                },
                visibilityConfig: {
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                    cloudWatchMetricsEnabled: true,
                    metricName: `${props.name}GqlPreventIntrospection`,
                },
            };
            rules.push(gqlPreventIntrospection);
        }

        if (props.allowList.length !== 0) {
            const ipSet = new CfnIPSet(this, props.name + '-ipset', {
                description: 'IPSet for Customer network public IP addresses',
                ipAddressVersion: 'IPV4',
                name: `${props.name}-allowed-ips`,
                scope: props.wafScope,
                addresses: props.allowList,
            });

            const allowedIPsRule: CfnWebACL.RuleProperty = {
                action: {
                    allow: {},
                },
                priority: 6,
                name: `${props.name}-AllowedIPs`,
                statement: {
                    ipSetReferenceStatement: {
                        arn: ipSet.attrArn,
                    },
                },
                visibilityConfig: {
                    cloudWatchMetricsEnabled: false,
                    metricName: `${props.name}AllowedIPSetRule`,
                    sampledRequestsEnabled: props.sampleRequestsEnabled,
                },
            };
            rules.push(allowedIPsRule);
        }

        this.webAcl = new CfnWebACL(this, `${props.name}-acl`, {
            name: `${props.name}-acl`,
            description: `${props.name}-acl`,
            defaultAction:
                props.allowList.length !== 0
                    ? {
                          block: {
                              ...(props.customResponseBody && {
                                  customResponse: props.customResponseBody,
                              }),
                          },
                      }
                    : {
                          allow: {},
                      },
            rules,
            ...(props.customResponseBodies && {
                customResponseBodies: props.customResponseBodies,
            }),
            scope: props.wafScope,
            visibilityConfig: {
                cloudWatchMetricsEnabled: true,
                metricName: `${props.name}WAFACL`,
                sampledRequestsEnabled: props.sampleRequestsEnabled,
            },
        });
    }
}
