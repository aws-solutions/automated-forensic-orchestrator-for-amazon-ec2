/* eslint-disable */
module.exports = {
    roots: ['<rootDir>'],
    modulePaths: ['<rootDir>'],
    testMatch: ['**/*.test.ts', '*.test.ts'],
    transform: {
        '^.+\\.tsx?$': 'ts-jest',
    },
    collectCoverage: true,
    collectCoverageFrom: ['src/**/*.ts', '!src/common/Xray.ts'],
    verbose: true,

    coverageThreshold: {
        global: {
            branches: 80,
            functions: 80,
            lines: 80,
            statements: -10,
        },
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
