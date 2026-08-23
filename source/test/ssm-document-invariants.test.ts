/*********************************************************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                *
 *                                                                                                                    *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    *
 *  with the License. A copy of the License is located at                                                             *
 *                                                                                                                    *
 *      http://www.apache.org/licenses/LICENSE-2.0                                                                    *
 *                                                                                                                    *
 *  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES  *
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    *
 *  and limitations under the License.                                                                                *
 *********************************************************************************************************************/

/**
 * Structural invariants for the SSM documents.
 *
 * These documents are the part of the solution that actually touches evidence,
 * and until now exactly one test covered them - asserting only that the
 * generated CfnDocument had DocumentType 'Command'. None of the shell logic was
 * covered, and every defect this file guards against shipped at least once:
 *
 *  - a shebang on line 2, where it is a comment (linux-disk-investigation-prepare)
 *  - a {{placeholder}} the document never declares, which SSM does not substitute
 *    (windows-lime-memory-acquisition referenced {{ AWS_ACCESS_KEY_ID }})
 *  - echoing an STS secret access key into output that is streamed to CloudWatch
 *  - calling plaso binaries natively on a host where only the container exists
 *    (windows-disk-investigation)
 *  - a runShellScript document with no failure handling that ends `exit 0;`
 *    whatever happened (both amazon-linux-2 builder documents)
 */

import * as fs from 'fs';
import * as path from 'path';

const DOCUMENT_DIR = path.join(__dirname, '..', 'ssm-documents');

interface SsmStep {
    action: string;
    name: string;
    inputs?: { runCommand?: string[]; [key: string]: unknown };
}

interface SsmDocument {
    schemaVersion: string;
    parameters?: Record<string, unknown>;
    mainSteps: SsmStep[];
}

const documentFiles = fs
    .readdirSync(DOCUMENT_DIR)
    .filter((name) => name.endsWith('.json'))
    .sort();

function load(name: string): SsmDocument {
    return JSON.parse(
        fs.readFileSync(path.join(DOCUMENT_DIR, name), 'utf-8')
    ) as SsmDocument;
}

function shellSteps(doc: SsmDocument): SsmStep[] {
    return doc.mainSteps.filter(
        (step) => step.action === 'aws:runShellScript' && step.inputs?.runCommand
    );
}

function scriptOf(step: SsmStep): string {
    return (step.inputs?.runCommand ?? []).join('\n');
}

/**
 * The executable lines of a step, with comment-only lines removed.
 *
 * The invariants below are about what the shell runs, not about the prose
 * explaining it: several of these documents now carry comments that name the
 * very command they exist to say is no longer used.
 */
function codeLines(doc: SsmDocument): string[] {
    return doc.mainSteps
        .flatMap((step) => step.inputs?.runCommand ?? [])
        .filter((line) => !/^\s*#/.test(line));
}

function codeOf(doc: SsmDocument): string {
    return codeLines(doc).join('\n');
}

describe('SSM document inventory', () => {
    it('discovers every document, so the suite below cannot be vacuous', () => {
        expect(documentFiles.length).toBeGreaterThanOrEqual(14);
    });

    it.each(documentFiles)('%s is schemaVersion 2.2 JSON', (name) => {
        const doc = load(name);
        expect(doc.schemaVersion).toEqual('2.2');
        expect(Array.isArray(doc.mainSteps)).toBe(true);
        expect(doc.mainSteps.length).toBeGreaterThan(0);
    });
});

describe('shell steps are executed by the interpreter they are written for', () => {
    it.each(documentFiles)('%s declares its shebang on line 1', (name) => {
        for (const step of shellSteps(load(name))) {
            const first = (step.inputs!.runCommand as string[])[0];
            // SSM runs the script with `sh -c <path>`, so a shebang anywhere
            // other than line 1 is a comment: the kernel returns ENOEXEC and sh
            // interprets the file itself, silently ignoring every bash-ism.
            expect(first).toMatch(/^#!\/bin\/(ba)?sh$/);
        }
    });

    it.each(documentFiles)('%s handles failure explicitly', (name) => {
        for (const step of shellSteps(load(name))) {
            const script = scriptOf(step);
            // Every one of these documents ends in `exit 0;`. Without a failure
            // path that means the step reports Success whatever happened, which
            // is how the tools loader reached CREATE_COMPLETE having produced
            // nothing and how a failed mount produced an empty timeline.
            if (/\bexit 0;?\s*$/.test(script)) {
                expect(script).toMatch(/fail\(\)\s*\{|_FAILED:/);
            }
        }
    });
});

describe('placeholders', () => {
    it.each(documentFiles)('%s only references declared parameters', (name) => {
        const doc = load(name);
        const declared = new Set(Object.keys(doc.parameters ?? {}));
        const referenced = new Set<string>();

        const body = codeOf(doc);
        for (const match of body.matchAll(/\{\{\s*([^}:]+?)\s*\}\}/g)) {
            referenced.add(match[1]);
        }

        const undeclared = [...referenced].filter((p) => !declared.has(p));
        // SSM leaves an undeclared placeholder unsubstituted, so the shell sees
        // the literal text. windows-lime-memory-acquisition referenced
        // {{ AWS_ACCESS_KEY_ID }}, which was never a parameter of that document.
        expect(undeclared).toEqual([]);
    });
});

describe('credentials are never echoed', () => {
    // Every acquisition and investigation document receives short lived STS
    // credentials as parameters, and SSM streams step output to CloudWatch Logs.
    const secretParameters = ['SecretAccessKey', 'SessionToken', 'SubscriptionManagerPassword'];

    it.each(documentFiles)('%s does not print a credential', (name) => {
        // Checked per line: an `echo` on one line and a credential assignment
        // twenty lines later are not the same statement.
        for (const line of codeLines(load(name))) {
            const prints = /\b(echo|Write-Output|Write-Host|printf)\b/i.test(
                line
            );
            if (!prints) {
                continue;
            }
            for (const secret of secretParameters) {
                expect(line).not.toMatch(
                    new RegExp(`\\{\\{\\s*${secret}\\s*\\}\\}`)
                );
            }
            expect(line).not.toMatch(/AWS_SECRET_ACCESS_KEY/);
            expect(line).not.toMatch(/AWS_SESSION_TOKEN/);
        }
    });
});

describe('plaso is invoked the way the analysis AMI provides it', () => {
    it.each(documentFiles)('%s runs plaso in its container', (name) => {
        const doc = load(name);
        const body = codeOf(doc);

        // forensic-analysis-tools.yml installs Docker and pre-pulls
        // log2timeline/plaso. It never installs plaso natively, so
        // `log2timeline.py` and `psort.py` do not exist on the analysis host.
        expect(body).not.toMatch(/\blog2timeline\.py\b/);
        expect(body).not.toMatch(/\bpsort\.py\b/);

        // The image runs as a non root user and the work area under /data is
        // root owned 0755, so every plaso container needs --user 0:0. The
        // previous revision bound /tmp, which is mode 1777 and therefore
        // writable by accident.
        for (const match of body.matchAll(/docker run([^"]*?)log2timeline\/plaso/g)) {
            expect(match[1]).toContain('--user 0:0');
        }
    });
});

describe('shell escaping survives the JSON layer', () => {
    /**
     * These documents are shell scripts stored as JSON string arrays, so every
     * backslash is escaped twice: once for JSON and once for the shell. Getting
     * that wrong does not break the script, it silently changes what the command
     * means, which is the worst possible outcome for a diagnostic.
     *
     * Observed live on 2026-08-21: `tr -d '\\000'` reached the shell instead of
     * `tr -d '\000'`, so instead of deleting NUL bytes it deleted backslashes and
     * the character '0'. A memory capture that was 97.7% NUL was reported as
     * "2086487539 of 2086711456 bytes non-zero" - the exact opposite of the
     * truth, in the single message telling the operator to re-acquire.
     */
    it.each(documentFiles)('%s deletes NUL bytes, not backslashes', (name) => {
        for (const line of codeLines(load(name))) {
            if (!line.includes('tr -d')) continue;
            // After JSON decoding the shell must see a single backslash.
            expect(line).not.toMatch(/tr -d '\\\\0/);
        }
    });

    it.each(documentFiles)('%s has no doubled backslash escapes at all', (name) => {
        for (const line of codeLines(load(name))) {
            // A literal double backslash in the decoded script is almost always
            // one JSON escaping level too many. None of these scripts needs one.
            expect(line).not.toContain('\\\\');
        }
    });
});

describe('acquisition refuses to report success for an unreadable capture', () => {
    /**
     * LiME intermittently returns a full-size image whose pages are almost
     * entirely zero and which contains no kernel banner: 3 of 9 acquisitions
     * observed, across Amazon Linux 2 kernel 4.14 and Amazon Linux 2023 kernels
     * 6.1 and 6.18. The only acquisition-side gate was a 65,536 byte floor on the
     * uploaded object, and a mostly-NUL 2 GiB capture gzips to far more than that
     * - one measured at 8.5 MB against 517 MB for a good capture of the same
     * host, and a synthetic reproduction of the same shape landed at 67,232 bytes,
     * i.e. it passed the floor by 1,696 bytes. So acquisition reported success and
     * the investigation was the first thing to notice, on another host, possibly
     * after the instance was gone.
     */
    const LINUX_ACQUISITION = 'linux_lime-memory-acquisition.json';

    it('counts the kernel banner while the capture streams', () => {
        const body = codeOf(load(LINUX_ACQUISITION));

        expect(body).toMatch(/grep -c 'Linux version '/);
        // From the stream, not by downloading the object back: the capture is
        // deliberately never written to the target's disk.
        expect(body).toMatch(/tee[^\n]*grep -c 'Linux version '/);
    });

    it('bounds the probe memory so it cannot OOM the capture', () => {
        const body = codeOf(load(LINUX_ACQUISITION));

        // Measured on a live AL2023 instance with GNU grep 3.8: a memory image
        // contains no newline for gigabytes, grep buffers a whole line, and 1 GB
        // of input cost 1.5 GiB of RSS. On a capture the size of the instance's
        // own RAM that is an OOM kill, which closes the pipe tee is writing to,
        // and with pipefail the whole capture then fails - which is exactly what
        // happened the first time this check was deployed. tr turns every
        // non-printable byte into a newline, so grep's buffer stays as short as
        // the longest printable run.
        expect(body).toMatch(
            /tr -c '\[:print:\]' '\\n'[^\n]*\|[^\n]*grep -c 'Linux version '/
        );
        // The unbounded form must not come back.
        expect(body).not.toMatch(/tee[^\n]*grep -a -c 'Linux version '/);
    });

    it('does not let the probe abort the capture with -m1', () => {
        const body = codeOf(load(LINUX_ACQUISITION));

        // grep -m1 exits after the first match, closing the pipe tee is writing
        // to; tee then fails and the capture dies. The probe must read the whole
        // stream.
        expect(body).not.toMatch(/grep[^\n|]*-m *1[^\n]*Linux version/);
    });

    it('keeps the probe off the pipe that feeds sha256sum', () => {
        // A process substitution inherits tee's stdout, which is the pipe feeding
        // sha256sum. This is exactly how the published digest came to be the hash
        // of the capture interleaved with CLI progress output. Every consumer must
        // redirect its own stdout.
        for (const line of codeLines(load(LINUX_ACQUISITION))) {
            if (!line.includes('tee >(')) continue;
            for (const consumer of line.matchAll(/>\(([^)]*)\)/g)) {
                expect(consumer[1]).toMatch(/>\s*("?\$?[\w/.{}"-]+|\/dev\/null)/);
            }
        }
    });

    it('rejects a capture that holds no banner, and only then', () => {
        const body = codeOf(load(LINUX_ACQUISITION));

        expect(body).toMatch(/\$hits" -eq 0/);
        expect(body).toMatch(/no kernel banner in \$\{uploaded_bytes\}/);
        // An empty probe is inconclusive, not negative. Rejecting an acquisition
        // on a timing artefact would discard real evidence and would also spend
        // the fallback tool for no reason, and the investigation still checks the
        // capture before analysing it.
        expect(body).toMatch(/if \[ -z "\$hits" \]/);
        expect(body).toMatch(/BANNER CHECK INCONCLUSIVE/);
    });

    it('preserves the capture it rejects', () => {
        const body = codeOf(load(LINUX_ACQUISITION));

        // Evidence is never deleted on this path - a partial capture may still be
        // worth something, and deleting evidence is worse than keeping a bad copy.
        // A rejected attempt survives as a previous version of the object, which
        // is why the artefact bucket's versioning is load bearing here.
        expect(body).not.toMatch(/(aws s3 rm|delete-object)/);
        expect(body).toMatch(/preserved as versions of/);
    });
});

describe('a corroborating plugin failure does not void a memory investigation', () => {
    /**
     * The rule used to be "any volatility3 plugin failed -> fail the case". On a
     * live Amazon Linux 2023 6.18.41 capture that reported
     * MEMORY_INVESTIGATION_FAILED for an investigation which had produced a
     * process list, argv, a scan-based process list and a plaso timeline, and
     * uploaded all of them - because linux.bash crashed inside volatility3
     * itself with "AttributeError: 'NoneType' object has no attribute 'i_size'"
     * walking a VMA with a null inode.
     *
     * That is the mirror of the bug the rule was introduced to fix. Reporting
     * failure when evidence exists is as wrong as reporting success when it does
     * not, and it would have hit every memory investigation on the current
     * default AL2023 AMI.
     */
    const DOC = 'lime-memory-load-investigation.json';

    it('only an essential plugin failure fails the step', () => {
        const body = codeOf(load(DOC));
        expect(body).toMatch(/if \[ "\$essential_failures" -gt 0 \]/);
        // The old unconditional rule must not come back.
        expect(body).not.toMatch(
            /if \[ "\$plugin_failures" -gt 0 \]; then\n\s*fail /
        );
    });

    it('treats the process list as essential and the rest as corroborating', () => {
        const body = codeOf(load(DOC));
        expect(body).toMatch(/run_plugin linux\.pslist \S+ essential/);
        for (const corroborating of ['linux.psaux', 'linux.psscan', 'linux.bash']) {
            const call = new RegExp(
                `run_plugin ${corroborating.replace('.', '\\.')} \\S+\\s*$`,
                'm'
            );
            expect(body).toMatch(call);
        }
    });

    it('still fails when no plugin produced anything', () => {
        // The floor stays: an investigation that produced nothing is a failure.
        const body = codeOf(load(DOC));
        expect(body).toMatch(/if \[ "\$plugins_ok" -eq 0 \]/);
        expect(body).toMatch(/no volatility3 plugin produced output/);
    });

    it('names the plugins that failed, so the gap is known not inferred', () => {
        const body = codeOf(load(DOC));
        expect(body).toMatch(/failed_plugins="\$failed_plugins \$1"/);
        expect(body).toMatch(/WARNING: volatility3 plugin\(s\) failed:\$failed_plugins/);
    });
});

describe('plaso runs the image the AMI pinned, never Docker Hub', () => {
    /**
     * The forensic AMI pulls plaso by SHA256 digest, records it at
     * /etc/forensic-analysis-plaso-image, and tags it locally as
     * log2timeline/plaso:latest. `docker run log2timeline/plaso` therefore resolves
     * to the pinned image with no pull - while the pre-pulled image is present. If
     * it is ever absent, the bare reference silently pulls :latest from Docker Hub
     * instead, and an examiner cannot tell which plaso produced a timeline.
     */
    it.each(documentFiles)('%s does not name the image inline', (name) => {
        for (const line of codeLines(load(name))) {
            if (line.trim().startsWith('#')) continue;
            if (!line.includes('docker run')) continue;
            expect(line).not.toMatch(/docker run[^\n]*\blog2timeline\/plaso\b/);
        }
    });

    it.each(documentFiles)('%s resolves the recorded digest and fails without it', (name) => {
        const body = codeOf(load(name));
        const runsPlaso = codeLines(load(name)).some(
            (line) => !line.trim().startsWith('#') && line.includes('docker run')
        );
        if (!runsPlaso) return;

        expect(body).toContain('/etc/forensic-analysis-plaso-image');
        // Absent pin must abort, not fall through to an unreviewed image.
        expect(body).toMatch(/plaso_image[^\n]*\|\| fail/);
    });
});
