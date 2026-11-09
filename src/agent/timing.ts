// Time-based blind injection oracle (explore.injection, timing branch).
//
// When no boolean differential and no error surface, a payload that makes the
// database SLEEP still proves injection: the response is delayed by the sleep. The
// proof is a MATCHED differential at the same injection point — the identical
// payload with sleep(0) (fast) vs sleep(N) (slow) — so network and endpoint latency
// cancel out. To stay at zero false positives in a noisy environment the bar is
// strict: several samples each, every slow sample slower than every fast sample
// (clean separation, no overlap), and the slow median ahead of the fast one by a
// large fraction of the sleep. Random jitter cannot satisfy non-overlap plus a
// seconds-wide margin. Pure, so it is tested without a network.

const median = (xs: number[]): number => { const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2; };

export function timingOracle(input: { fast: number[]; slow: number[]; sleepMs: number }): { verdict: "proven" | "lead" | "denied"; reason: string } {
  const { fast, slow, sleepMs } = input;
  if (fast.length < 3 || slow.length < 3) return { verdict: "lead", reason: "not enough timing samples to decide" };
  const mf = median(fast), ms = median(slow), delta = ms - mf;
  const maxFast = Math.max(...fast), minSlow = Math.min(...slow);
  // Clean separation: no slow sample overlaps any fast sample.
  if (minSlow <= maxFast) return { verdict: "denied", reason: `fast and slow timings overlap (slowest fast ${Math.round(maxFast)}ms >= fastest slow ${Math.round(minSlow)}ms): no reliable delay` };
  if (delta < 0.6 * sleepMs) return { verdict: "lead", reason: `the slow payload is only ${Math.round(delta)}ms slower (sleep asked ${sleepMs}ms): below the margin, review by hand` };
  return { verdict: "proven", reason: `the sleep payload is consistently ${Math.round(delta)}ms slower (sleep ${sleepMs}ms, every slow sample above every fast one): a time-based injection` };
}
