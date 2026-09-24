import { describe, it, expect } from "vitest";
import { runWithConcurrency } from "../src/utils/concurrency.js";

describe("runWithConcurrency", () => {
  it("never exceeds the configured concurrency cap", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 40 }, (_, i) => i);

    await runWithConcurrency(items, { concurrency: 4 }, async (i) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return i * 2;
    });

    expect(maxInFlight).toBeLessThanOrEqual(4);
  });

  it("preserves result order regardless of completion order", async () => {
    const items = [30, 10, 20, 5];
    const results = await runWithConcurrency(items, { concurrency: 4 }, async (ms) => {
      await new Promise((r) => setTimeout(r, ms));
      return ms;
    });
    expect(results).toEqual([30, 10, 20, 5]);
  });

  it("respects pacing delay between dispatches", async () => {
    const items = [1, 2, 3, 4];
    const start = Date.now();
    await runWithConcurrency(items, { concurrency: 1, paceMs: 30 }, async (i) => i);
    const elapsed = Date.now() - start;
    // 4 items, concurrency 1, 30ms pacing between dispatches after the first => at least ~90ms.
    expect(elapsed).toBeGreaterThanOrEqual(80);
  });

  it("runs all items even when concurrency exceeds item count", async () => {
    const results = await runWithConcurrency([1, 2], { concurrency: 100 }, async (i) => i * 10);
    expect(results).toEqual([10, 20]);
  });
});
