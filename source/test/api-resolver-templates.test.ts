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

import * as fs from 'fs';
import * as path from 'path';

/**
 * The API's resolver templates, rendered and checked.
 *
 * Nothing validated these. They are text assets uploaded to AppSync, so a
 * template can be wrong in a way that produces no error at deploy time and no
 * error at query time - it just quietly does something other than what it says.
 * That is exactly what had happened: **pagination did not work on any list
 * query**, in two independent ways.
 *
 *   1. Every template read `$ctx.args.limit` and `$ctx.args.nextToken`, but the
 *      schema declares both *inside* the input object - `input.limit`,
 *      `input.nextToken` - so the `#if` guards were never true and both
 *      arguments were dropped. Measured against the deployed API: a
 *      `timelineEventsForRecord` query asking for `limit: 2` returned all six
 *      events, and `allForensicRecords` asking for `limit: 1` returned every
 *      record in the table.
 *   2. The six Query templates put `limit` and `nextToken` *inside* the `"query"`
 *      object. The AppSync DynamoDB Query mapping-template reference puts them at
 *      the top level, as siblings of `query` alongside `index` and
 *      `scanIndexForward`, so AppSync ignored them there too.
 *
 * The consequence for a forensic API is not cosmetic: a case with more items than
 * one DynamoDB page returns a truncated list together with a `nextToken` the
 * caller has no way to use, so evidence past the first page is unreachable, and a
 * caller that does implement paging is served the same first page forever.
 *
 * The templates also carried trailing commas - `{"#PK": "PK", "#SK": "SK",}` and
 * a `},}` in the GetItem key - which are not valid JSON. AppSync tolerated them,
 * so they were harmless in practice and are removed here rather than relied upon.
 */

const REQUEST_DIR = path.join(__dirname, '..', 'api', 'request-mapping-templates');
const RESPONSE_DIR = path.join(__dirname, '..', 'api', 'response-mapping-templates');
const SCHEMA = path.join(__dirname, '..', 'api', 'forensics-api.gql');

/**
 * A renderer for the VTL subset these templates use: `#if(...)` / `#end`,
 * `$util.toJson(x)`, `$util.dynamodb.toDynamoDBJson(x)`, and `$ctx.args...` /
 * `${ctx.args...}` / `$context.arguments...` references.
 *
 * Deliberately small. Its only job is to answer "with these arguments, what JSON
 * does AppSync receive?", which is the question nothing was asking.
 */
function render(template: string, args: Record<string, unknown>): string {
    const lookup = (expr: string): unknown => {
        const parts = expr
            .replace(/^\$\{?/, '')
            .replace(/\}$/, '')
            .replace(/^context\.arguments/, 'args')
            .replace(/^ctx\.args/, 'args')
            .replace(/^context\.args/, 'args')
            .split('.');
        let value: unknown = { args };
        for (const part of parts) {
            if (value === null || value === undefined) return undefined;
            value = (value as Record<string, unknown>)[part];
        }
        return value;
    };

    // #if( expr ) ... #end - truthy when the referenced value is present.
    let out = template;
    const ifBlock = /#if\(\s*([^)]+?)\s*\)([\s\S]*?)#end/g;
    out = out.replace(ifBlock, (_m, expr: string, body: string) => {
        const value = lookup(expr.trim());
        return value === undefined || value === null || value === false
            ? ''
            : body;
    });

    // $util.dynamodb.toDynamoDBJson(...) -> a typed value
    out = out.replace(
        /\$util\.dynamodb\.toDynamoDBJson\(\s*([^)]*?)\s*\)/g,
        (_m, inner: string) => {
            const resolved = inner.startsWith('"')
                ? inner
                      .slice(1, -1)
                      .replace(/\$\{[^}]+\}/g, (ref) => String(lookup(ref) ?? ''))
                : String(lookup(inner) ?? '');
            return JSON.stringify({ S: resolved.replace(/^"|"$/g, '') });
        }
    );

    // $util.defaultIfNullOrBlank(a, b) first: it appears *inside* a toJson call
    // in list-response.vtl, and resolving the outer call first would swallow it.
    out = out.replace(
        /\$util\.defaultIfNullOrBlank\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)/g,
        (_m, a: string, fallback: string) => {
            const value = lookup(a);
            if (value !== undefined && value !== null && value !== '') {
                return JSON.stringify(value);
            }
            return fallback.trim() === 'null' ? 'null' : JSON.stringify(fallback);
        }
    );

    // $util.toJson(...) - the argument may already be rendered JSON by now.
    out = out.replace(/\$util\.toJson\(\s*([^)]*?)\s*\)/g, (_m, inner: string) => {
        const trimmed = inner.trim();
        if (trimmed === 'null') return 'null';
        if (!trimmed.startsWith('$')) return trimmed;
        return JSON.stringify(lookup(trimmed) ?? null);
    });

    // Any remaining bare reference.
    out = out.replace(/\$\{?(?:ctx|context)[\w.[\]]*\}?/g, (ref) =>
        JSON.stringify(lookup(ref) ?? null)
    );
    return out;
}

const requestTemplates = fs
    .readdirSync(REQUEST_DIR)
    .filter((f) => f.endsWith('.vtl'));

/** Which templates issue a DynamoDB Query or Scan, i.e. can paginate. */
function operationOf(name: string): string {
    const body = fs.readFileSync(path.join(REQUEST_DIR, name), 'utf-8');
    return body.match(/"operation"\s*:\s*"(\w+)"/)?.[1] ?? 'none';
}

const paginating = requestTemplates.filter((n) =>
    ['Query', 'Scan'].includes(operationOf(n))
);

describe('resolver templates render to valid JSON', () => {
    it('found the templates, so nothing below is vacuous', () => {
        expect(requestTemplates.length).toBeGreaterThanOrEqual(9);
        expect(paginating.length).toBeGreaterThanOrEqual(7);
    });

    const argumentSets: Array<[string, Record<string, unknown>]> = [
        ['no optional arguments', { id: 'r1', input: { id: 'r1', awsAccountId: '1', awsRegion: 'us-east-1', resourceType: 'INSTANCE', resourceId: 'i-1' } }],
        ['limit only', { id: 'r1', input: { id: 'r1', awsAccountId: '1', awsRegion: 'us-east-1', resourceType: 'INSTANCE', resourceId: 'i-1', limit: 25 } }],
        ['nextToken only', { id: 'r1', input: { id: 'r1', awsAccountId: '1', awsRegion: 'us-east-1', resourceType: 'INSTANCE', resourceId: 'i-1', nextToken: 'tok' } }],
        ['limit and nextToken', { id: 'r1', input: { id: 'r1', awsAccountId: '1', awsRegion: 'us-east-1', resourceType: 'INSTANCE', resourceId: 'i-1', limit: 25, nextToken: 'tok' } }],
    ];

    for (const name of requestTemplates) {
        for (const [label, args] of argumentSets) {
            it(`${name} renders valid JSON with ${label}`, () => {
                const body = fs.readFileSync(path.join(REQUEST_DIR, name), 'utf-8');
                const rendered = render(body, args);
                // A trailing or doubled comma is invalid JSON. Supplying `limit`
                // used to produce `}, ,"limit": 25` in the Query templates,
                // because the guard emitted a leading comma after a block that
                // already ended in one.
                expect(() => JSON.parse(rendered)).not.toThrow();
            });
        }
    }

    it.each(fs.readdirSync(RESPONSE_DIR).filter((f) => f.endsWith('.vtl')))(
        '%s renders valid JSON',
        (name) => {
            const body = fs.readFileSync(path.join(RESPONSE_DIR, name), 'utf-8');
            const rendered = render(body, {
                result: { items: [], nextToken: null },
            });
            expect(() => JSON.parse(rendered)).not.toThrow();
        }
    );
});

describe('pagination reaches DynamoDB', () => {
    it.each(paginating)('%s reads limit and nextToken from the schema path', (name) => {
        const body = fs.readFileSync(path.join(REQUEST_DIR, name), 'utf-8');
        // The schema declares both inside the input object, so reading
        // $ctx.args.limit silently drops them - verified against the deployed
        // API, where limit: 2 returned all six items.
        expect(body).toMatch(/\$ctx\.args\.input\.limit/);
        expect(body).toMatch(/\$ctx\.args\.input\.nextToken/);
        expect(body).not.toMatch(/\$\{?ctx\.args\.limit/);
        expect(body).not.toMatch(/\$\{?context\.arguments\.limit/);
        expect(body).not.toMatch(/\$\{?ctx\.args\.nextToken/);
        expect(body).not.toMatch(/\$\{?context\.arguments\.nextToken/);
    });

    it.each(paginating.filter((n) => operationOf(n) === 'Query'))(
        '%s puts limit and nextToken beside query, not inside it',
        (name) => {
            const body = fs.readFileSync(path.join(REQUEST_DIR, name), 'utf-8');
            const queryStart = body.indexOf('"query"');
            expect(queryStart).toBeGreaterThan(-1);
            // Brace-match the query object.
            let depth = 0;
            let end = -1;
            for (let i = body.indexOf('{', queryStart); i < body.length; i++) {
                if (body[i] === '{') depth++;
                else if (body[i] === '}') {
                    depth--;
                    if (depth === 0) {
                        end = i;
                        break;
                    }
                }
            }
            const insideQuery = body.slice(queryStart, end);
            // Per the AppSync Query mapping-template reference these are
            // top-level fields, siblings of query.
            expect(insideQuery).not.toMatch(/limit/);
            expect(insideQuery).not.toMatch(/nextToken/);
        }
    );

    it('every paginating query exposes the arguments in the schema', () => {
        const schema = fs.readFileSync(SCHEMA, 'utf-8');
        // Both directions matter: a resolver that reads an argument the schema
        // does not declare is dead code, and a schema that declares one no
        // resolver reads is a promise the API does not keep.
        for (const input of [
            'AllRecordsInput',
            'TimelineEventsForRecordInput',
            'ArtifactsForRecordInput',
            'ListRecordsForAccountInput',
            'ListRecordsForRegionInput',
            'ListRecordsForResourceTypeInput',
            'ListRecordsForResourceInput',
        ]) {
            const block = schema.match(
                new RegExp(`input\\s+${input}\\s*\\{([^}]*)\\}`)
            );
            expect(block).not.toBeNull();
            expect(block![1]).toMatch(/nextToken\s*:\s*String/);
            expect(block![1]).toMatch(/limit\s*:\s*Int/);
        }
    });
});
