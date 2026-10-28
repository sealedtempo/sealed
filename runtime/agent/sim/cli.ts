// node dist/sim.js --app-compose <file> (--socket <path> | --port <n>) [--host 127.0.0.1] [--debug]
import { parseArgs } from "node:util";
import { startSimulator } from "./simulator.js";

const usage = "usage: sealed-dstack-sim --app-compose <file> (--socket <path> | --port <n>) [--host <addr>] [--debug]";

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      "app-compose": { type: "string" },
      socket: { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      debug: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help || !values["app-compose"] || (!values.socket && !values.port)) {
    console.error(usage);
    process.exit(values.help ? 0 : 2);
  }
  const sim = await startSimulator({
    appComposePath: values["app-compose"],
    socket: values.socket,
    port: values.port ? Number(values.port) : undefined,
    host: values.host,
    debug: values.debug,
  });
  console.log(
    JSON.stringify({
      msg: "dstack simulator listening (SIMULATED QUOTES, dev only)",
      endpoint: sim.endpoint,
      composeHash: sim.state.composeHash,
      rtmr3: sim.state.rtmr3,
      debug: sim.state.debug,
    }),
  );
  const stop = () => void sim.close().then(() => process.exit(0));
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
