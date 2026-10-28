// Step log for the devnet run: numbered steps with elapsed times, one line per check, and a summary.
export interface StepRecord {
  n: number;
  name: string;
  ms: number;
  /** Assertions (check/checkEq calls) that passed in this step. */
  checks: number;
}

let assertions = 0;
/** Assertions passed so far in this process. */
export const assertionCount = () => assertions;

export class StepLog {
  readonly started = Date.now();
  readonly steps: StepRecord[] = [];
  private current?: StepRecord & { t0: number; a0: number };
  private readonly out: (line: string) => void;

  constructor(out: (line: string) => void = (l) => process.stdout.write(`${l}\n`)) {
    this.out = out;
  }

  private stamp(): string {
    return `[${((Date.now() - this.started) / 1000).toFixed(1).padStart(6)}s]`;
  }

  step(name: string): void {
    this.end();
    const n = this.steps.length + 1;
    this.current = { n, name, ms: 0, checks: 0, t0: Date.now(), a0: assertions };
    this.out(`\n${this.stamp()} == ${n}. ${name}`);
  }

  /** A passed group of assertions. */
  ok(msg: string): void {
    this.out(`${this.stamp()}    ok   ${msg}`);
  }

  info(msg: string): void {
    this.out(`${this.stamp()}    ..   ${msg}`);
  }

  warn(msg: string): void {
    this.out(`${this.stamp()}    warn ${msg}`);
  }

  end(): void {
    if (!this.current) return;
    const { t0, a0, ...rest } = this.current;
    this.steps.push({ ...rest, checks: assertions - a0, ms: Date.now() - t0 });
    this.current = undefined;
  }

  get checks(): number {
    return this.steps.reduce((s, x) => s + x.checks, 0) + (this.current ? assertions - this.current.a0 : 0);
  }

  summary(result: "PASS" | "FAIL"): string[] {
    this.end();
    const lines = [``, `${result} devnet-e2e: ${this.steps.length} steps, ${this.checks} assertions, total ${((Date.now() - this.started) / 1000).toFixed(1)} s`];
    for (const s of this.steps) lines.push(`  ${String(s.n).padStart(2)}. ${s.name.slice(0, 78).padEnd(78)} ${(s.ms / 1000).toFixed(1).padStart(6)} s ${String(s.checks).padStart(4)} assertions`);
    return lines;
  }
}

/** Thrown by `check` with the failing assertion. */
export class CheckFailed extends Error {}

export function check(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new CheckFailed(msg);
  assertions++;
}

export function checkEq<T>(actual: T, expected: T, what: string): void {
  const a = typeof actual === "string" ? actual.toLowerCase() : actual;
  const e = typeof expected === "string" ? expected.toLowerCase() : expected;
  if (a !== e) throw new CheckFailed(`${what}: expected ${String(expected)}, got ${String(actual)}`);
  assertions++;
}
