module.exports = {
    roots: ['<rootDir>/test'],
    testMatch: ['**/*.test.ts'],
    collectCoverage: true,
    /**
     * Serial. Four suites synthesize a stack, and synthesizing builds the Lambda
     * dependency layer into one fixed directory (`.build/lambda-common`), which
     * `installDependencies` clears with `rm -rf` before repopulating. Run in
     * parallel, one suite can delete that directory while another is reading it
     * for `Code.fromAsset`, which fails intermittently - observed once in six
     * runs and not reproducible on demand, which is the worst kind of CI
     * failure for a contributor to inherit.
     *
     * The alternative is to key the staging directory per worker
     * (JEST_WORKER_ID) or to cache on a hash of the requirements file. Both are
     * better; neither is worth the risk in this change set, and the whole suite
     * runs in about a minute serially.
     */
    maxWorkers: 1,
    transform: {
        '^.+\\.tsx?$': 'ts-jest',
    },
    reporters: [
        'default',
        [
            'jest-junit',
            {
                outputDirectory: './reports',
                outputName: 'test_report.xml',
            },
        ],
    ],
};
