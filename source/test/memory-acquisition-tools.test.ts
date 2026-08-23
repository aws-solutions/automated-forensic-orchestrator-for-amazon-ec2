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

import { MEMORY_ACQUISITION_TOOLS } from '../lib/infra-utils/infra-types';

/**
 * The dual-mechanism memory acquisition contract.
 *
 * Linux memory is acquired by trying LiME and then AVML, in the order given by
 * the memoryAcquisitionTools parameter, with the kernel banner check deciding
 * whether a capture is usable and therefore whether to try the next tool.
 *
 * The reason there are two: LiME intermittently returns a full-size image whose
 * pages are almost entirely zero and which contains no kernel banner - 3 of 9
 * acquisitions observed here, across Amazon Linux 2 kernel 4.14 and Amazon Linux
 * 2023 kernels 6.1 and 6.18, cause not isolated. Retrying LiME would share
 * whatever that cause is. AVML does not: it reads /dev/crash, /dev/mem or
 * /proc/kcore rather than loading a kernel module, so the two fail
 * independently. Both write LiME format, so nothing downstream needs to know
 * which one ran - but an examiner does, which is why provenance is in the
 * object's metadata.
 *
 * Every assertion here corresponds to something that was wrong at some point
 * while this was built, and that no other gate would have caught:
 *   - an unpinned LiME clone compiling the default branch of the day into the
 *     kernel of the machine under investigation,
 *   - a fallback keyed on exit status, which is 0 for the exact failure that
 *     motivated the fallback,
 *   - "$LIME_ORIGIN$AVML_ORIGIN" in the metadata, which recorded the provenance
 *     of a capture as "stubstub-release",
 *   - sending memoryAcquisitionTools to a document that does not declare it,
 *     which SSM rejects with InvalidParameters, so the acquisition never starts.
 */

const SOURCE_ROOT = path.join(__dirname, '..');
const DOCUMENT = path.join(
    SOURCE_ROOT,
    'ssm-documents',
    'linux_lime-memory-acquisition.json'
);
const HANDLER = path.join(
    SOURCE_ROOT,
    'lambda',
    'src',
    'acquisition',
    'performMemoryAcquisition.py'
);

const document = JSON.parse(fs.readFileSync(DOCUMENT, 'utf-8'));
const script: string = document.mainSteps[0].inputs.runCommand.join('\n');
/** Executable lines only: the comments quote the mistakes, and that is worth keeping. */
const code: string = script
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n');

const TOOLS = MEMORY_ACQUISITION_TOOLS.split(',').map((t) => t.trim());

describe('both acquisition mechanisms are present and reachable', () => {
    it('the CDK default names tools the document can actually run', () => {
        expect(TOOLS.length).toBeGreaterThanOrEqual(2);
        for (const tool of TOOLS) {
            // Each has to be a case in the dispatch, or it silently becomes
            // "unknown acquisition tool" and the list is one shorter than the
            // operator thinks it is.
            expect(code).toMatch(new RegExp(`^\\s*${tool}\\)\\s*$`, 'm'));
        }
    });

    it('the document default matches the CDK default', () => {
        // Two defaults for one value. If they drift, the document's own default
        // is what runs for anyone invoking it outside the state machine, and the
        // env var is what runs inside - two different acquisition strategies
        // depending on the entry point.
        expect(document.parameters.memoryAcquisitionTools.default).toEqual(
            MEMORY_ACQUISITION_TOOLS
        );
    });

    it('tries each tool in turn rather than stopping at the first', () => {
        expect(code).toMatch(/for tool in \$requested/);
        // A `continue` per unavailable tool, and a `break` only once something
        // was captured: an unavailable first tool must not end the loop.
        expect(code).toMatch(/reasons="\$reasons lime:unavailable"; continue/);
        expect(code).toMatch(/reasons="\$reasons avml:unavailable"; continue/);
        expect(code).toMatch(/captured=\$tool; "\$cleanup"; break/);
    });

    it('refuses an empty tool list instead of exiting 0 having done nothing', () => {
        // The loop body never runs for an empty list, `captured` stays empty,
        // and without this the operator gets a bare "no acquisition tool
        // produced a usable capture after 0 attempt(s)".
        expect(code).toMatch(/\[ "\$total" -gt 0 \] \|\| fail/);
    });

    it('reports the attempt against the number of tools requested', () => {
        // "attempt 1 of 1" was wrong whenever a later tool was still available.
        expect(code).toMatch(/on attempt \$attempt of \$total/);
        expect(code).not.toMatch(/of \$\{attempt\}/);
    });
});

describe('the fallback is driven by the capture, not by the exit status', () => {
    it('checks the uploaded capture before accepting it', () => {
        // The failure that motivated all of this exits 0: LiME streams a
        // full-size image, gzip compresses it, the upload succeeds, sha256sum
        // agrees with itself. Keying the fallback on `if "$streamer" | ...`
        // alone would never fall back.
        expect(code).toMatch(/why=\$\(verify_capture "\$attempt"\) &&/);
        expect(code).toMatch(/hits=\$\(cat "\$banner_probe"/);
    });

    it('a rejected capture records why and moves to the next tool', () => {
        expect(code).toMatch(
            /echo "\$tool produced an unusable capture: \$why"/
        );
        expect(code).toMatch(/reasons="\$reasons \$tool:\$\(printf/);
    });

    it('clears the probe between attempts', () => {
        // Without this the second tool inherits the first tool's banner count -
        // in the direction that matters, a zero from LiME would reject a good
        // AVML capture, or a stale positive from a good tool would accept a bad
        // one.
        const loop = code.slice(code.indexOf('for tool in $requested'));
        expect(loop).toMatch(/rm -f "\$banner_probe"/);
    });

    it('an inconclusive check does not spend the fallback', () => {
        // The probe is written by a process substitution that bash does not
        // wait for, so an empty probe means "do not know", not "no banner". A
        // fallback there would re-image the host over a timing artefact and
        // overwrite a possibly good capture with a second attempt.
        expect(code).toMatch(/if \[ -z "\$hits" \][\s\S]{0,400}?return 0/);
    });
});

describe('both tools are pinned, and AVML is verified by digest', () => {
    it('pins LiME to a tag in the repository that hosts it', () => {
        expect(code).toMatch(/^LIME_REF=v\d+\.\d+\.\d+$/m);
        // 504ensicsLabs/LiME redirects to jtsylve/LiME. Cloning the old path
        // works only while GitHub honours the redirect and would resolve
        // somewhere else entirely if the old name were reclaimed - into a kernel
        // module loaded on the machine under investigation.
        expect(code).toMatch(/^LIME_REPO=https:\/\/github\.com\/jtsylve\/LiME\.git$/m);
        expect(code).toMatch(/git clone --depth 1 --branch "\$LIME_REF" "\$LIME_REPO"/);
        expect(code).not.toMatch(/504ensicsLabs/);
    });

    it('selects the release asset for the target architecture', () => {
        // The release ships a build per architecture. Downloading the x86_64
        // asset onto a Graviton target produced a binary that cannot execute, so
        // AVML was unavailable on exactly the architecture where it is the only
        // option: LiME needs a kernel module, and no aarch64 module can be
        // staged - only compiled in the guest. Verified on a live m7g.large,
        // where the capture's provenance now reads
        // acquisition-tool-origin=release-v0.20.0-avml-aarch64.
        expect(code).toMatch(/case "\$\(uname -m\)" in/);
        expect(code).toMatch(/x86_64\)\s*\n\s*AVML_ASSET=avml\n/);
        expect(code).toMatch(/aarch64\|arm64\)\s*\n\s*AVML_ASSET=avml-aarch64/);
        expect(code).toMatch(/releases\/download\/\$\{AVML_VERSION\}\/\$\{AVML_ASSET\}/);
        // One digest per asset - a single pin cannot verify two binaries.
        const digests = [...code.matchAll(/AVML_SHA256=([0-9a-f]{64})/g)];
        expect(digests.length).toBeGreaterThanOrEqual(2);
        expect(new Set(digests.map((m) => m[1])).size).toEqual(digests.length);
        // An unsupported machine type is named, not guessed at.
        expect(code).toMatch(/publishes no build for \$\(uname -m\)/);
        // and the recorded provenance distinguishes which asset ran
        expect(code).toMatch(/AVML_ORIGIN=release-\$AVML_VERSION-\$AVML_ASSET/);
    });

    it('pins AVML to a release and a 64-hex digest', () => {
        expect(code).toMatch(/^AVML_VERSION=v\d+\.\d+\.\d+$/m);
        // Indented: the digests live in a per-architecture case block.
        expect(code).toMatch(/^\s*AVML_SHA256=[0-9a-f]{64}$/m);
        expect(code).toMatch(
            /releases\/download\/\$\{AVML_VERSION\}\/\$\{AVML_ASSET\}/
        );
    });

    it('verifies the AVML digest before the binary is made executable', () => {
        const download = code.indexOf('releases/download/${AVML_VERSION}');
        const compare = code.indexOf('"$actual" != "$AVML_SHA256"');
        const executable = code.indexOf('chmod +x "$W/avml"');

        expect(download).toBeGreaterThan(-1);
        expect(compare).toBeGreaterThan(download);
        // Ordering is the whole control. A digest checked after chmod +x, or
        // after the first run, verifies something that already executed.
        expect(executable).toBeGreaterThan(compare);
        expect(code).toMatch(/failed digest verification - expected/);
    });

    it('does not verify an operator-staged binary against the upstream digest', () => {
        // A staged binary is the operator's provenance, not GitHub's - it is how
        // a host with no route to the internet still gets imaged, and it is the
        // same contract the RHEL document already uses. Comparing it to the
        // upstream digest would reject every legitimately staged build.
        const resolve = code.slice(code.indexOf('avml_resolve()'));
        const staged = resolve.slice(0, resolve.indexOf('\n    else\n'));
        expect(staged).toMatch(/AVML_ORIGIN=staged/);
        // and the digest is only in the branch that downloaded the binary
        expect(staged).not.toContain('AVML_SHA256');
        expect(resolve).toContain('AVML_SHA256');
    });
});

describe('an attempt only accepts the object it wrote itself', () => {
    it('confirms the stored capture belongs to this attempt', () => {
        // The key is the same on every attempt. If a second attempt's upload
        // fails *after* tee has finished, the pipeline still succeeds and
        // head-object returns the *first* attempt's object - which was then
        // accepted, given the second tool's name in the log, and published with
        // the first tool's digest and metadata. Verified in a container by
        // failing attempt 2's upload after it consumed all of stdin.
        expect(code).toMatch(/local for_attempt=\$1/);
        expect(code).toMatch(
            /stored_attempt=\$\([^\n]*Metadata\."acquisition-attempt"/
        );
        expect(code).toMatch(/\[ "\$stored_attempt" != "\$for_attempt" \]/);
        expect(code).toMatch(/was written by attempt \$\{stored_attempt:-unknown\}/);
        // and the attempt number is actually passed in
        expect(code).toMatch(/why=\$\(verify_capture "\$attempt"\)/);
    });
});

describe('the recorded tool version is the version that ran', () => {
    it('asks the binary rather than trusting the pin', () => {
        // An operator-staged binary can be any build. Recording the pinned
        // version would attribute the capture to a version that never ran, which
        // for evidence is a false provenance claim rather than a cosmetic slip.
        expect(code).toMatch(
            /AVML_REPORTED_VERSION=\$\("\$AVML_BIN" --version[^\n]*\)/
        );
        expect(code).toMatch(/tool_version=v\$AVML_REPORTED_VERSION/);
        // The pin must not be what lands in the metadata.
        expect(code).not.toMatch(/tool_version=\$AVML_VERSION/);
    });

    it('a binary that cannot run fails immediately and by name', () => {
        // Otherwise the listener waits out its 180 second accept timeout for a
        // connection that can never come, and reports nothing useful.
        expect(code).toMatch(/if \[ -z "\$AVML_REPORTED_VERSION" \]/);
        expect(code).toMatch(/does not run - cannot acquire with it/);
    });

    it('notes, but does not fail on, a release disagreeing with its pin', () => {
        // The digest already proved which bytes ran, so a version string
        // mismatch is information, not grounds to refuse to image a host.
        expect(code).toMatch(/reports itself as \$AVML_REPORTED_VERSION/);
    });
});

describe('the capture records which tool produced it', () => {
    const metadata =
        code.match(/^\s*meta="([^"]+)"/m)?.[1] ??
        (() => {
            throw new Error('no metadata assignment found');
        })();

    it.each([
        'acquisition-tool=$tool',
        'acquisition-tool-version=$tool_version',
        'acquisition-tool-origin=$tool_origin',
        'acquisition-attempt=$attempt',
    ])('records %s', (field) => {
        expect(metadata).toContain(field);
    });

    it('is attached to the capture object itself', () => {
        expect(code).toMatch(/s3cp "\.lime\.gz"[^\n]*--metadata "\$meta"/);
    });

    it('uses one origin variable rather than concatenating both tools', () => {
        // "${LIME_ORIGIN}${AVML_ORIGIN}" recorded a capture's provenance as
        // "stubstub-release": whichever tool did not run contributed its empty
        // string, and when both had run it contributed the wrong one.
        expect(code).not.toMatch(/\$\{?LIME_ORIGIN\}?\$\{?AVML_ORIGIN\}?/);
        expect(code).toMatch(/tool_origin=\$LIME_ORIGIN/);
        expect(code).toMatch(/tool_origin=\$AVML_ORIGIN/);
    });
});

describe('the two tools do not interfere with each other', () => {
    it('unloads the LiME module whether or not it produced a capture', () => {
        // A module left in the kernel holds 127.0.0.1:4444, which is the port
        // AVML is told to stream to on the next attempt - AVML would connect to
        // LiME and the "AVML" capture would be LiME's output.
        expect(code).toMatch(/lime_cleanup\(\) \{ sudo rmmod lime/);
        expect(code).toMatch(/^\s*"\$cleanup"$/m);
    });

    it('reaps AVML in the subshell that started it, not in the cleanup', () => {
        // avml_stream runs as an element of a pipeline, and bash runs each
        // element in a subshell, so a pid recorded there is invisible to the
        // parent - a kill in avml_cleanup silently never fires. A surviving AVML
        // dials 4444 during a later attempt, which is the port LiME listens on,
        // and would consume that capture out from under the pipeline.
        const stream = code.slice(
            code.indexOf('avml_stream()'),
            code.indexOf('avml_cleanup()')
        );
        // exec, so $! is AVML's own pid rather than the subshell's.
        expect(stream).toMatch(/\( sleep \d+; exec "\$AVML_BIN" stream tcp/);
        expect(stream).toMatch(/local avml_pid=\$!/);
        expect(stream).toMatch(/kill "\$avml_pid"[\s\S]*wait "\$avml_pid"/);
        // The listener's status is what the pipeline sees, not wait's.
        expect(stream).toMatch(/return \$listener_status/);

        const cleanup = code.slice(code.indexOf('avml_cleanup()'));
        expect(cleanup.slice(0, cleanup.indexOf('\n}'))).not.toMatch(/kill/);
        // pkill would have been the other option and is not in the Amazon Linux
        // 2023 base image, so it would silently not apply.
        expect(code).not.toMatch(/pkill/);
    });

    it('keeps the capture off the target disk for both tools', () => {
        // The point of streaming: nothing about the acquisition modifies the
        // filesystem of the machine under investigation. AVML can write a file
        // and LiME can take path=/some/file; neither may here.
        expect(code).toMatch(/"\$AVML_BIN" stream tcp 127\.0\.0\.1:4444/);
        expect(code).toMatch(/path=tcp:4444/);
        expect(code).not.toMatch(/avml"? +[^ ]*\.lime\b/);
    });
});

describe('the second mechanism is available on the hosts that need it', () => {
    it('resolves the interpreter instead of assuming python3', () => {
        // The stock Amazon Linux 2 EC2 AMI does ship python3 - measured on a live
        // 4.14.355 instance, which has both python3 and python2.7 - but the
        // amazonlinux:2 container image ships only python2.7, so a host built from
        // a minimal base, or with python3 removed, would silently lose the
        // fallback. AL2 kernel 4.14 is one of the kernels on which LiME produced
        // an unusable capture, so it is the last place to accept an assumption in
        // exchange for nothing. Byte-exactness under python2 was verified for a
        // 4 MB transfer, and a full AVML acquisition was driven by python2 alone.
        expect(code).toMatch(
            /for candidate in python3 python2 python; do[\s\S]{0,200}?LISTEN_PY=\$candidate/
        );
        expect(code).toMatch(/"\$LISTEN_PY" "\$W\/listen\.py" 4444/);
        // python3 may appear in the candidate list, but nothing may invoke it
        // directly - that is, python3 followed by a script, path or variable.
        expect(code).not.toMatch(/python3 [">$/]/);
    });

    it('the listener script is valid under both python versions', () => {
        const listener = script.slice(
            script.indexOf("<<'PYEOF'") + 9,
            script.indexOf('PYEOF', script.indexOf("<<'PYEOF'") + 9)
        );
        expect(listener).toContain('socket');
        // print(), f-strings and str/bytes conversions are the usual ways this
        // breaks. Byte-exactness under python2 was verified for a 4 MB transfer.
        expect(listener).not.toMatch(/\bprint\(/);
        expect(listener).not.toMatch(/f"/);
        expect(listener).not.toMatch(/\.encode\(|\.decode\(/);
        // Binary and unbuffered, or the capture is corrupted by newline
        // translation and truncated by buffering.
        expect(listener).toMatch(/os\.fdopen\(sys\.stdout\.fileno\(\), "wb", 0\)/);
    });

    it('relocates AVML when the working directory is mounted noexec', () => {
        // CIS hardening puts noexec on /tmp, and chmod cannot undo a mount
        // option, so AVML would be silently unavailable on exactly the hardened
        // hosts most worth imaging. Verified by remounting /tmp noexec in a
        // container: the binary moved to /var/tmp and the capture succeeded.
        expect(code).toMatch(/exec_permitted\(\) \{/);
        // The property is tested directly, not inferred from mount options.
        expect(code).toMatch(/printf '#!\/bin\/sh\\nexit 0\\n' > "\$probe"/);
        expect(code).toMatch(/if ! exec_permitted "\$W" ; then/);
        expect(code).toMatch(/for exec_dir in \/var\/tmp\/forensic_tools \/run\/forensic_tools/);
        // And it says so rather than failing obscurely when nowhere works.
        expect(code).toMatch(/no directory permits execution/);
    });
});

describe('two attempts share one step timeout', () => {
    it('refuses an attempt that cannot finish inside the budget', () => {
        // timeoutSeconds is {{ExecutionTimeout}} and SSM kills the whole command
        // when it expires. One capture used to have the entire budget. A second
        // attempt killed mid-stream yields neither a capture nor a diagnostic -
        // just a timed-out command - so the loop refuses to start one, using the
        // previous attempt's duration as the estimate. They stream the same RAM.
        expect(code).toMatch(/BUDGET_SECONDS='\{\{ExecutionTimeout\}\}'/);
        expect(code).toMatch(/remaining=\$\(\(BUDGET_SECONDS - SECONDS\)\)/);
        expect(code).toMatch(
            /\[ "\$remaining" -lt "\$last_attempt_seconds" \]/
        );
        expect(code).toMatch(/attempt_started=\$SECONDS/);
        expect(code).toMatch(
            /last_attempt_seconds=\$\(\(SECONDS - attempt_started\)\)/
        );
    });

    it('names the setting that fixes it', () => {
        // "the command timed out" sends the reader nowhere.
        expect(code).toMatch(/Raise ssmExecutionTimeout/);
        expect(code).toMatch(/reasons="\$reasons \$tool:not-enough-time-left"/);
    });

    it('a non-numeric budget disables the check rather than breaking the loop', () => {
        // ExecutionTimeout is a String parameter, so it can arrive as anything.
        // `[ "$remaining" -lt ... ]` on a non-number is a fatal shell error, and
        // it would abort an acquisition over a formatting problem.
        expect(code).toMatch(
            /case "\$BUDGET_SECONDS" in\n''\|\*\[!0-9\]\*\) BUDGET_SECONDS=0 ;;/
        );
        expect(code).toMatch(/\[ "\$BUDGET_SECONDS" -gt 0 \]/);
    });

    it('the handler sends the timeout, so the budget is not the document default', () => {
        const handler = fs.readFileSync(HANDLER, 'utf-8');
        expect(handler).toMatch(
            /params\["ExecutionTimeout"\] = \[\s*os\.environ\.get\("SSM_EXECUTION_TIMEOUT"/
        );
    });
});

describe('only the document that declares the parameter is sent it', () => {
    const handler = fs.readFileSync(HANDLER, 'utf-8');
    const handlerCode = handler
        .split('\n')
        .filter((line) => !line.trim().startsWith('#'))
        .join('\n');

    it('the generic Linux document declares memoryAcquisitionTools', () => {
        expect(document.parameters.memoryAcquisitionTools).toBeDefined();
        expect(document.parameters.memoryAcquisitionTools.type).toEqual('String');
    });

    it('no other acquisition document is sent it', () => {
        const documentDir = path.join(SOURCE_ROOT, 'ssm-documents');
        const others = fs
            .readdirSync(documentDir)
            .filter(
                (name) =>
                    name.endsWith('.json') &&
                    name.includes('memory-acquisition') &&
                    name !== 'linux_lime-memory-acquisition.json'
            );
        // Guards against this passing because the glob matched nothing.
        expect(others.length).toBeGreaterThan(0);

        for (const name of others) {
            const other = JSON.parse(
                fs.readFileSync(path.join(documentDir, name), 'utf-8')
            );
            expect(Object.keys(other.parameters ?? {})).not.toContain(
                'memoryAcquisitionTools'
            );
        }
    });

    it('the handler gates the parameter on the document it is sending to', () => {
        // SSM rejects the whole send_command with InvalidParameters when a
        // parameter is not declared. Sending this unconditionally would not
        // misconfigure the RHEL and Windows acquisitions - it would stop them.
        expect(handlerCode).toMatch(
            /if \(\s*memory_acquisition_document_name\s*==\s*linux_memory_acquisition_document_name\s*\)/
        );
        const guarded = handlerCode.slice(
            handlerCode.indexOf('linux_memory_acquisition_document_name\n')
        );
        expect(guarded).toMatch(
            /params\["memoryAcquisitionTools"\] = \[\s*os\.environ\.get\(\s*"MEMORY_ACQUISITION_TOOLS"/
        );
    });

    it('falls back to the same default the CDK and the document use', () => {
        expect(handlerCode).toMatch(
            new RegExp(`"MEMORY_ACQUISITION_TOOLS", "${MEMORY_ACQUISITION_TOOLS}"`)
        );
    });
});
