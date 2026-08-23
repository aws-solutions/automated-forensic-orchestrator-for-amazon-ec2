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

import js from '@eslint/js';
import prettierConfig from 'eslint-config-prettier';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    {
        // Replaces the `ignorePatterns` from the previous .eslintrc. Flat config decides
        // scope from `files`/`ignores` rather than from `--ext`, so the `*.js`/`*.cjs`/
        // `*.mjs` entries are what preserve the TypeScript-only scope this project lints
        // with, whether or not the caller passes `--ext .ts`.
        ignores: [
            'cdk.out/**',
            'dist/**',
            'coverage/**',
            '.build/**',
            '**/*.js',
            '**/*.cjs',
            '**/*.mjs',
        ],
    },
    js.configs.recommended,
    tseslint.configs.recommended,
    prettierConfig,
    {
        files: ['**/*.ts'],
        rules: {
            // Successor to `@typescript-eslint/no-var-requires`, which typescript-eslint v8
            // folded into this rule. Kept off so the `import x = require('...')` form used
            // by the CDK stacks and tests continues to lint clean.
            '@typescript-eslint/no-require-imports': 'off',
            '@typescript-eslint/no-inferrable-types': 'off',
            '@typescript-eslint/ban-ts-comment': 'off',
            // typescript-eslint v6 promoted every `recommended` rule to `error` and dropped
            // `no-non-null-assertion` from the set. The three entries below restore the
            // severities this project linted against under v5 so that upgrading the linter
            // does not, by itself, change which findings block a build.
            '@typescript-eslint/no-explicit-any': 'warn',
            '@typescript-eslint/no-non-null-assertion': 'warn',
            '@typescript-eslint/no-unused-vars': 'warn',
            'no-undef': 0,
            'no-func-assign': 0,
            'padding-line-between-statements': [
                'error',
                {
                    blankLine: 'always',
                    prev: ['export', 'class'],
                    next: '*',
                },
            ],
        },
    }
);
