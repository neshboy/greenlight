/**
 * A small concurrency-capped task runner. This exists specifically so that
 * every network-probing module (port scanning, subdomain enumeration) goes
 * through a single, auditable chokepoint that enforces:
 *   - a hard cap on concurrent in-flight connections
 *   - optional per-dispatch pacing delay
 *
 * This is Greenlight's primary defense against being (mis)used as a
 * denial-of-service tool: no module is allowed to open unbounded parallel
 * connections to a target.
 */
export interface PoolOptions {
  /** Maximum number of tasks in flight at once. Must be >= 1. */
  concurrency: number;
  /** Optional minimum delay (ms) between dispatching successive tasks. */
  paceMs?: number;
}

export async function runWithConcurrency<T, R>(
  items: T[],
  opts: PoolOptions,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const concurrency = Math.max(1, Math.floor(opts.concurrency));
  const paceMs = opts.paceMs ?? 0;
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function runOne(): Promise<void> {
    while (true) {
      const i = nextIndex++;
      if (i >= items.length) return;
      if (paceMs > 0 && i > 0) {
        await sleep(paceMs);
      }
      results[i] = await worker(items[i], i);
    }
  }

  const workerCount = Math.min(concurrency, items.length);
  const runners: Promise<void>[] = [];
  for (let i = 0; i < workerCount; i++) {
    runners.push(runOne());
  }
  await Promise.all(runners);
  return results;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
