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

import { SSM_OUTPUT_LOG_GROUP_PREFIX } from '../lib/infra-utils/infra-types';

/**
 * The archived output of every SSM command this solution sends depends on two
 * independent pieces agreeing on one string:
 *
 *   - the Lambdas, which tell the agent what to call the log group, and
 *   - the instance role, which is granted logs:CreateLogGroup on a prefix.
 *
 * If they drift the agent is denied, no log group is created, and the archiving
 * silently becomes a no-op. That is not hypothetical: until this change the
 * grant did not exist at all, so `CloudWatchOutputEnabled: true` had never once
 * produced a log group, and every failing memory investigation was diagnosed
 * from SSM's 24 KB-truncated output - which volatility3's progress output alone
 * overflows, so the lines that said why were the lines that got cut.
 *
 * Nothing about that failure is visible at runtime: send_command succeeds, the
 * command runs, and the absent log group looks exactly like a command that had
 * nothing to say. Hence a test.
 */

const LAMBDA_SRC = path.join(__dirname, '..', 'lambda', 'src');
const COMMON_PY = path.join(LAMBDA_SRC, 'common', 'common.py');

function read(file: string): string {
    return fs.readFileSync(file, 'utf-8');
}

function walk(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) return walk(full);
        return entry.name.endsWith('.py') ? [full] : [];
    });
}

describe('SSM output log group', () => {
    it('uses the same prefix in the CDK and in the Lambdas', () => {
        const pythonPrefix = read(COMMON_PY).match(
            /SSM_OUTPUT_LOG_GROUP_PREFIX\s*=\s*"([^"]+)"/
        );

        expect(pythonPrefix).not.toBeNull();
        expect(pythonPrefix![1]).toEqual(SSM_OUTPUT_LOG_GROUP_PREFIX);
    });

    it('is a prefix an IAM policy can be scoped to', () => {
        // A bare forensic id cannot be scoped to anything narrower than every
        // log group in the account, which is why the grant did not exist.
        expect(SSM_OUTPUT_LOG_GROUP_PREFIX.startsWith('/')).toBe(true);
        expect(SSM_OUTPUT_LOG_GROUP_PREFIX).not.toMatch(
            /^\/?[0-9a-f]{8}-[0-9a-f]{4}/
        );
    });

    it('is what every Lambda names its log group', () => {
        const offenders: string[] = [];

        for (const file of walk(LAMBDA_SRC)) {
            const source = read(file);
            for (const line of source.split('\n')) {
                if (!line.includes('CloudWatchLogGroupName')) continue;
                // The name must come from the shared helper, so the prefix is
                // applied in exactly one place.
                if (!line.includes('ssm_output_log_group(')) {
                    offenders.push(`${path.relative(LAMBDA_SRC, file)}: ${line.trim()}`);
                }
            }
        }

        expect(offenders).toEqual([]);
    });

    it('is applied by the helper, not by each caller', () => {
        const common = read(COMMON_PY);

        expect(common).toMatch(/def ssm_output_log_group\(/);
        // The helper has to actually prepend the prefix; a helper that returns
        // its argument unchanged would satisfy every other test here.
        expect(common).toMatch(
            /return f"\{SSM_OUTPUT_LOG_GROUP_PREFIX\}\/\{name\}"/
        );
    });
});
