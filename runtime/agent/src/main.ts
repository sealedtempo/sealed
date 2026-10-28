import { Agent } from "./agent.js";
import { createLogger, errorFields } from "./log.js";
import { settingsFromEnv } from "./settings.js";

export async function main(): Promise<void> {
  const log = createLogger({ svc: "sealed-agent" });
  let agent: Agent | undefined;
  const shutdown = (sig: string) => {
    log.info("shutting down", { signal: sig });
    void (agent?.stop() ?? Promise.resolve()).then(() => process.exit(0));
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  try {
    agent = new Agent({
      settings: settingsFromEnv(),
      log,
      // The privileged Caddy helper cannot be restarted after the privilege drop: exit so Docker restarts the agent.
      onFatal: () => process.exit(1),
    });
    await agent.boot();
    agent.start();
  } catch (err) {
    log.error("boot failed", errorFields(err));
    process.exit(1);
  }
}
