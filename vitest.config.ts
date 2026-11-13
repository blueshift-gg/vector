import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 60_000,
    projects: [
      {
        // No validator needed.
        test: {
          name: "offline",
          include: ["sdk/ts/test/**/*.test.ts"],
          exclude: ["sdk/ts/test/**/*.e2e.test.ts"],
        },
      },
      {
        // Needs `bun run validator` running, with the program built.
        test: {
          name: "e2e",
          include: ["sdk/ts/test/**/*.e2e.test.ts"],
        },
      },
    ],
  },
});
