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

/**
 * Every Lambda `handler` string must name a Python module that really exists,
 * compared case-sensitively.
 *
 * Two functions shipped unable to import their own handler. `Fo-checkAcquisition`
 * declared `src.acquisition.checkAcquisition` against a file named
 * `checkacquisition.py`, and it is the second state of the triage state machine
 * with no Catch, so every triage execution aborted with
 * Runtime.ImportModuleError before reaching acquisition. It survived review
 * because macOS and Windows resolve the import case-insensitively: the module
 * loads locally and only Lambda's case-sensitive Linux rejects it.
 *
 * `fs.existsSync` is therefore useless here — on a case-insensitive filesystem
 * it returns true for the wrong casing, which is exactly how the defect got
 * through. This asserts against a directory listing instead, so it fails on a
 * developer laptop rather than in an incident.
 */

import * as fs from 'fs';
import * as path from 'path';

const LAMBDA_ROOT = path.resolve(__dirname, '..', 'lambda');
const CONSTRUCT_DIR = path.resolve(__dirname, '..', 'lib');

/** Recursively collect every .ts file under lib/. */
const typescriptSources = (dir: string): string[] =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) return typescriptSources(full);
        return entry.isFile() && entry.name.endsWith('.ts') ? [full] : [];
    });

/**
 * Case-sensitive existence check. Compares against the real directory listing
 * rather than asking the filesystem to resolve the path for us.
 */
const existsCaseSensitively = (absolutePath: string): boolean => {
    const dir = path.dirname(absolutePath);
    if (!fs.existsSync(dir)) return false;
    return fs.readdirSync(dir).includes(path.basename(absolutePath));
};

interface DeclaredHandler {
    handler: string;
    source: string;
}

const declaredHandlers = (): DeclaredHandler[] => {
    // e.g. handler: 'src.acquisition.checkacquisition.lambda_handler',
    const pattern = /handler:\s*['"]((?:src|lambda)[\w.]*)['"]/g;
    return typescriptSources(CONSTRUCT_DIR).flatMap((file) => {
        const text = fs.readFileSync(file, 'utf-8');
        return [...text.matchAll(pattern)].map((m) => ({
            handler: m[1],
            source: path.relative(CONSTRUCT_DIR, file),
        }));
    });
};

describe('Lambda handler resolution', () => {
    const handlers = declaredHandlers();

    it('finds handler declarations to check', () => {
        // Guards against the regex silently matching nothing after a refactor,
        // which would make every assertion below vacuously pass.
        expect(handlers.length).toBeGreaterThan(20);
    });

    it.each(handlers.map((h) => [h.handler, h.source]))(
        '%s (declared in %s) resolves to a module file that exists, case-sensitively',
        (handler, source) => {
            // Strip the trailing function name: the rest is the module path.
            const modulePath = handler.split('.').slice(0, -1).join('/');
            const absolute = path.join(LAMBDA_ROOT, `${modulePath}.py`);

            expect({
                handler,
                declaredIn: source,
                expectedFile: path.relative(LAMBDA_ROOT, absolute),
                exists: existsCaseSensitively(absolute),
            }).toEqual(
                expect.objectContaining({ exists: true })
            );
        }
    );

    it('rejects a handler whose module differs only by case', () => {
        // Proves the check is genuinely case-sensitive rather than relying on
        // the host filesystem, which is the whole point of this file.
        const realFile = path.join(
            LAMBDA_ROOT,
            'src',
            'acquisition',
            'checkacquisition.py'
        );
        const wrongCase = path.join(
            LAMBDA_ROOT,
            'src',
            'acquisition',
            'checkAcquisition.py'
        );

        expect(existsCaseSensitively(realFile)).toBe(true);
        expect(existsCaseSensitively(wrongCase)).toBe(false);
    });
});
