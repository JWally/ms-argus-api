import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['src/**/*.test.ts', 'lib/**/*.test.ts'],
    exclude: ['node_modules', 'dist', 'cdk.out', 'cmd'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'json-summary', 'lcov'],
      include: ['src/**/*.ts', 'lib/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'lib/**/*.test.ts',
        'src/**/*.d.ts',
        'lib/**/*.d.ts',
        'node_modules',
        'dist',
      ],
      thresholds: {
        statements: 25,
        branches: 40,
        functions: 25,
        lines: 25,
      },
    },
  },
});
