// JSON-lines logger. Secrets must never be passed in; as a second line of defence, fields whose
// names look like key material are replaced before writing.
export type Level = "debug" | "info" | "warn" | "error";
export type Fields = Record<string, unknown>;

const SENSITIVE = /(secret|password|seed|privatekey|private_key|diskkey|enclave_key|plaintext|bcrypt|authorization)/i;
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface Logger {
  debug(msg: string, fields?: Fields): void;
  info(msg: string, fields?: Fields): void;
  warn(msg: string, fields?: Fields): void;
  error(msg: string, fields?: Fields): void;
  child(fields: Fields): Logger;
}

export function scrub(value: unknown, depth = 0): unknown {
  if (depth > 6 || value === null || typeof value !== "object") {
    return typeof value === "bigint" ? value.toString() : value;
  }
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE.test(k) ? "[redacted]" : scrub(v, depth + 1);
  }
  return out;
}

export function errorFields(err: unknown): Fields {
  if (err instanceof Error) {
    const short = (err as { shortMessage?: string }).shortMessage;
    return { error: short ?? err.message.split("\n")[0] };
  }
  return { error: String(err) };
}

export function createLogger(
  base: Fields = {},
  opts: { level?: Level; write?: (line: string) => void } = {},
): Logger {
  const min = ORDER[opts.level ?? ((process.env.SEALED_LOG_LEVEL as Level) || "info")] ?? ORDER.info;
  const write = opts.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const emit = (level: Level, msg: string, fields?: Fields) => {
    if (ORDER[level] < min) return;
    const rec = { t: new Date().toISOString(), level, msg, ...(scrub({ ...base, ...fields }) as Fields) };
    write(JSON.stringify(rec));
  };
  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
    child: (fields) => createLogger({ ...base, ...fields }, opts),
  };
}

export const silentLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return silentLogger;
  },
};
