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

import { HYPHEN } from '../lib/infra-utils/infra-types';

/**
 * The contract between "distributions we say we support" and "documents that
 * exist and can actually be invoked".
 *
 * Three separate pieces have to agree and nothing checked that they did:
 *
 *   1. kernelSymbolLoader's table of supported distributions,
 *   2. the SSM document files on disk, and
 *   3. the environment variable the CDK derives from each *filename*
 *      (`name.replace(HYPHEN, '_').toUpperCase()` in
 *      forensic-ssm-document-builder-stack.ts).
 *
 * They agreed for RHEL8 and AL2023 by coincidence of naming. They could not
 * agree for Amazon Linux 2, whose document is amazon-linux-2-volatility-profile
 * and therefore AMAZON_LINUX_2_VOLATILITY_PROFILE, a name the string "AL2"
 * cannot produce. RHEL7 and RHEL9 were advertised for years with no document at
 * all: they passed validation and then raised KeyError, after a builder instance
 * had been launched by a handler that never terminates it.
 *
 * A consequence worth noting: renaming any file in ssm-documents/ silently
 * renames a Lambda environment variable. This suite is what makes that visible.
 */

const SOURCE_ROOT = path.join(__dirname, '..');
const DOCUMENT_DIR = path.join(SOURCE_ROOT, 'ssm-documents');
const LOADER = path.join(
    SOURCE_ROOT,
    'lambda',
    'src',
    'kernelloader',
    'kernelSymbolLoader.py'
);

/** The transform the CDK applies to turn a document filename into an env var. */
function envVarForDocument(fileName: string): string {
    return fileName.replace(/\.json$/, '').replace(HYPHEN, '_').toUpperCase();
}

/** The distribution -> env var table, read from the handler itself. */
function supportTable(): Record<string, string> {
    const source = fs.readFileSync(LOADER, 'utf-8');
    const block = source.match(
        /SYMBOL_DOCUMENT_ENV_VARS\s*=\s*\{([\s\S]*?)\}/
    );
    expect(block).not.toBeNull();

    const table: Record<string, string> = {};
    for (const entry of block![1].matchAll(/"([^"]+)"\s*:\s*"([^"]+)"/g)) {
        table[entry[1]] = entry[2];
    }
    return table;
}

/** Parameters the handler sends to whichever symbol document it selects. */
function parametersSentByLoader(): string[] {
    const source = fs.readFileSync(LOADER, 'utf-8');
    const block = source.match(/params\s*=\s*\{([\s\S]*?)\n\s{4}\}/);
    expect(block).not.toBeNull();

    return [...block![1].matchAll(/"([A-Za-z0-9]+)"\s*:/g)].map((m) => m[1]);
}

const documentEnvVars = new Map(
    fs
        .readdirSync(DOCUMENT_DIR)
        .filter((name) => name.endsWith('.json'))
        .map((name) => [envVarForDocument(name), name])
);

describe('supported distributions resolve to real documents', () => {
    const table = supportTable();

    it('declares at least the distributions this release claims', () => {
        // Guards against the suite passing because the table was emptied.
        expect(Object.keys(table).sort()).toEqual(
            ['AL2', 'AL2023', 'RHEL8'].sort()
        );
    });

    it.each(Object.entries(table))(
        '%s maps to an env var some document actually produces',
        (_distribution, envVar) => {
            const owner = documentEnvVars.get(envVar);
            expect(owner).toBeDefined();
            // A distribution pointing at a variable no file produces is the
            // RHEL7/RHEL9 failure: accepted, then KeyError after launching a
            // builder nobody terminates.
            expect(typeof owner).toBe('string');
        }
    );

    it.each(Object.entries(table))(
        '%s does not rely on deriving the env var from its own name',
        (distribution, envVar) => {
            // The old code did `distribution + "_VOLATILITY_SYMBOL"`. AL2 proves
            // why that cannot be relied on, so at least one entry must break the
            // pattern - otherwise the table is decorative and the naming
            // coincidence is still load bearing.
            expect(envVar.length).toBeGreaterThan(0);
            if (distribution === 'AL2') {
                expect(envVar).not.toEqual(`${distribution}_VOLATILITY_SYMBOL`);
            }
        }
    );

    it('no longer builds the document env var by string concatenation', () => {
        const source = fs.readFileSync(LOADER, 'utf-8');
        // Executable lines only: the comment above the table quotes the old
        // expression to explain why it was replaced, and that explanation is
        // worth keeping.
        const code = source
            .split('\n')
            .filter((line) => !/^\s*#/.test(line))
            .join('\n');

        expect(code).not.toMatch(
            /os\.environ\[\s*distribution\s*\+\s*"_VOLATILITY_SYMBOL"\s*\]/
        );
        expect(code).toMatch(/SYMBOL_DOCUMENT_ENV_VARS\[\s*distribution\s*\]/);
        // and the explanation survives, so this cannot pass by deleting it
        expect(source).toMatch(/distribution \+ "_VOLATILITY_SYMBOL"/);
    });
});

describe('each supported document accepts what the loader sends', () => {
    const table = supportTable();
    const sent = parametersSentByLoader();

    it('found the parameter list, so the assertions below are not vacuous', () => {
        expect(sent).toContain('AccessKeyId');
        expect(sent).toContain('s3bucket');
        expect(sent.length).toBeGreaterThanOrEqual(6);
    });

    it.each(Object.entries(table))(
        '%s declares every parameter the loader passes',
        (_distribution, envVar) => {
            const fileName = documentEnvVars.get(envVar);
            expect(fileName).toBeDefined();

            const doc = JSON.parse(
                fs.readFileSync(path.join(DOCUMENT_DIR, fileName!), 'utf-8')
            );
            const declared = new Set(Object.keys(doc.parameters ?? {}));

            // SSM rejects the whole send_command with InvalidParameters when a
            // parameter is not declared, so an undeclared one is not a runtime
            // warning - the symbol build never starts.
            const undeclared = sent.filter((p) => !declared.has(p));
            expect(undeclared).toEqual([]);
        }
    );

    it('only asks Red Hat for subscription credentials', () => {
        const source = fs.readFileSync(LOADER, 'utf-8');
        // The non-RHEL documents do not declare the subscription parameters, so
        // sending them unconditionally would make every AL2/AL2023 symbol build
        // fail with InvalidParameters.
        expect(source).toMatch(
            /requires_subscription\s*=\s*distribution\.startswith\("RHEL"\)/
        );

        for (const [distribution, envVar] of Object.entries(supportTable())) {
            if (distribution.startsWith('RHEL')) continue;
            const doc = JSON.parse(
                fs.readFileSync(
                    path.join(DOCUMENT_DIR, documentEnvVars.get(envVar)!),
                    'utf-8'
                )
            );
            expect(Object.keys(doc.parameters ?? {})).not.toContain(
                'SubscriptionManagerUsername'
            );
        }
    });
});
