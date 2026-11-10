import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/support/global-setup.ts'],
    // Integration tests share one Postgres; run files sequentially.
    fileParallelism: false,
    // pg-boss contract tests wait on real expiry/supervision timers.
    testTimeout: 30_000,
  },
});
