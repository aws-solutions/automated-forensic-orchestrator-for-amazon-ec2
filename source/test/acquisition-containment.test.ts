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
 * Containment when the memory acquisition status check fails.
 *
 * The status check already caught its errors to the failure chain, so a failure
 * was reported and the execution ended cleanly - but isolation sits further down
 * the happy path and was skipped. That is backwards for the case that actually
 * occurs: observed live, the status check failed because the target had stopped
 * answering SSM, which is exactly when containment matters. Isolation itself does
 * not need SSM; it swaps the security group, revokes sessions and sets
 * termination protection through the EC2 and IAM APIs, all of which still work
 * against a host that has gone dark.
 *
 * These assertions are on the construct source rather than a synthesized
 * definition, because the DefinitionString is a Fn::Join of CloudFormation
 * tokens and asserting on it tests the join, not the routing.
 */

const SOURCE = fs.readFileSync(
    path.join(
        __dirname,
        '..',
        'lib',
        'forensic-orchestrator',
        'acquisition',
        'memory-acquisition-step-functions.ts'
    ),
    'utf-8'
);

describe('memory acquisition contains the target before it gives up', () => {
    it('routes a status-check failure through the containment choice', () => {
        // Not straight to memoryAcquisitionFailedChain, which is what skipped
        // isolation.
        expect(SOURCE).toMatch(
            /checkMemoryAcquisitionCompletion\.addCatch\(\s*containBeforeFailing/
        );
    });

    it('keeps the state input so the isolation flag survives the catch', () => {
        // Without resultPath the error object replaces the input entirely, the
        // flag is gone, and every caught failure takes the otherwise branch -
        // which would make this whole path dead code.
        const catcher = SOURCE.match(
            /checkMemoryAcquisitionCompletion\.addCatch\(([\s\S]*?)\);/
        );
        expect(catcher).not.toBeNull();
        expect(catcher![1]).toMatch(/resultPath:\s*'\$\.error'/);
    });

    it('only isolates when isolation was actually requested', () => {
        // Containment is an intrusive action. A triage that did not ask for it
        // must behave exactly as before.
        expect(SOURCE).toMatch(/isPresent\('\$\.Payload\.body\.isIsolationNeeded'\)/);
        expect(SOURCE).toMatch(
            /booleanEquals\(\s*'\$\.Payload\.body\.isIsolationNeeded',\s*true\s*\)/
        );
        expect(SOURCE).toMatch(/\.otherwise\(memoryAcquisitionFailedChain\)/);
    });

    it('still fails the execution after containing', () => {
        // The acquisition failed either way. Isolating must not turn a failed
        // acquisition into a success, and must not divert into the investigation.
        expect(SOURCE).toMatch(
            /isolateAfterAcquisitionFailure\.next\(memoryAcquisitionFailedChain\)/
        );
        expect(SOURCE).not.toMatch(
            /isolateAfterAcquisitionFailure\.next\(investigationTask\)/
        );
    });

    it('does not let a failed isolation hide the acquisition failure', () => {
        expect(SOURCE).toMatch(
            /isolateAfterAcquisitionFailure\.addCatch\(memoryAcquisitionFailedChain\)/
        );
    });

    it('uses its own state rather than rewiring the happy-path isolation', () => {
        // triggerForensicsIsolation already has a next state (the investigation);
        // a state can only have one. Reusing it would send a failed acquisition
        // into the investigation.
        expect(SOURCE).toMatch(
            /triggerForensicsIsolation\.next\(investigationTask\)/
        );
        expect(SOURCE).toMatch(
            /const isolateAfterAcquisitionFailure = new LambdaInvoke/
        );
    });
});

describe('dwarf2json comes from the project that owns it', () => {
    const DOC = path.join(
        __dirname,
        '..',
        'ssm-documents',
        'amazon-linux-2-volatility-profile.json'
    );

    function lines(): string[] {
        const doc = JSON.parse(fs.readFileSync(DOC, 'utf-8'));
        return doc.mainSteps.flatMap(
            (s: { inputs?: { runCommand?: string[] } }) => s.inputs?.runCommand ?? []
        );
    }

    /** Executable lines only: the comment explaining what was removed names it. */
    function script(): string {
        return lines()
            .filter((line) => !/^\s*#/.test(line))
            .join('\n');
    }

    it('no longer fetches a binary from an individual repository', () => {
        // It used to pull dwarf2json off the default branch of
        // kevthehermit/volatility_symbols, unpinned and unverified, then run it
        // against the kernel's debug symbols.
        expect(script()).not.toContain('kevthehermit');
        // The comment recording why is expected to survive, so this test cannot
        // pass by the explanation being deleted along with the code.
        expect(lines().join('\n')).toContain('kevthehermit');
    });

    it('takes the volatilityfoundation release, pinned by tag', () => {
        const body = script();
        expect(body).toMatch(
            /volatilityfoundation\/dwarf2json\/releases\/download\/\$\{DWARF2JSON_VERSION\}/
        );
        expect(body).toMatch(/DWARF2JSON_VERSION=v\d+\.\d+\.\d+/);
    });

    it('verifies the digest and refuses to run a mismatch', () => {
        const body = script();
        expect(body).toMatch(/DWARF2JSON_SHA256=[0-9a-f]{64}/);
        expect(body).toMatch(/sha256sum dwarf2json/);
        // A warning is not enough: a mismatch means the binary about to read this
        // kernel's symbols is not the reviewed one.
        expect(body).toMatch(/dwarf2json_actual.*\|\| fail/s);
        // and the digest must be checked before it is made executable
        const checkAt = body.indexOf('dwarf2json_actual');
        const chmodAt = body.indexOf('chmod +x dwarf2json');
        expect(checkAt).toBeGreaterThan(-1);
        expect(chmodAt).toBeGreaterThan(checkAt);
    });
});
