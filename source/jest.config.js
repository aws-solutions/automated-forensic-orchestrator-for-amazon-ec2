module.exports = {
    roots: ['<rootDir>/test'],
    testMatch: ['**/*.test.ts'],
    collectCoverage: true,
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
