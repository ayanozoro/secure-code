import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/benchmarks/**',
      '**/fixtures/**',
      '**/.git/**',
      '**/.turbo/**',
      '**/.husky/**'
    ]
  }
});
