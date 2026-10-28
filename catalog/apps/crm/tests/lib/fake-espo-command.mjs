#!/usr/bin/env node
// Stand-in for EspoCRM's bin/command (10.0) for the bootstrap tests. It changes the state file
// that fake-espocrm.mjs serves, with the exit codes and messages of the upstream commands
// (Classes\ConsoleCommands\*, Core\Console\Commands\SetPassword). Usage:
//   FAKE_ESPO_STATE=<state.json> fake-espo-command.mjs <command> [args...]
// state.failOnce = <command> makes that command exit 1 once (crash and re-run tests).

import { readFileSync } from "node:fs";

import { mergedConfig, readState, writeState } from "./fake-espocrm.mjs";

const file = process.env.FAKE_ESPO_STATE;
const [command, ...args] = process.argv.slice(2);
const state = readState(file);
state.calls.push([command, ...args]);
const out = (line) => process.stdout.write(`${line}\n`);
const exit = (code) => {
  writeState(file, state);
  process.exit(code);
};

if (state.failOnce === command) {
  state.failOnce = undefined;
  out(`${command} failed`);
  exit(1);
}

const needsDb = ["config:populate", "rebuild", "create-admin-user", "set-password", "populate-scheduled-jobs", "app-check", "db:check", "migrate"];
if (needsDb.includes(command) && !state.dbUp) {
  process.stderr.write("Not connected\n");
  exit(1);
}

switch (command) {
  case "config:get": {
    const config = { isInstalled: false, version: "10.0.11", ...mergedConfig(state) };
    if (!(args[0] in config)) {
      out(`Parameter '${args[0]}' is not set in config.`);
      exit(1);
    }
    const v = config[args[0]];
    out(v === true ? "true" : v === false ? "false" : v === null ? "null" : typeof v === "object" ? JSON.stringify(v) : String(v));
    exit(0);
  }
  case "config:set": {
    const type = (args.find((a) => a.startsWith("--type=")) ?? "--type=string").slice(7);
    const [name, raw] = args.filter((a) => !a.startsWith("--"));
    const value = type === "bool" ? raw === "true" : type === "int" ? Number(raw) : raw;
    if (name.includes(".")) {
      const [a, b] = name.split(".");
      state.config[a] = { ...(state.config[a] ?? {}), [b]: value };
    } else {
      state.config[name] = value;
    }
    exit(0);
  }
  case "config:populate":
    state.populated = true;
    state.config = { version: "10.0.11", userNameRegularExpression: "[^a-z0-9\\-@_\\.\\s]", ...state.config };
    exit(0);
  case "rebuild":
    if (!state.populated) exit(1);
    state.rebuilt = true;
    exit(0);
  case "db:check":
    out("OK");
    exit(0);
  case "create-admin-user": {
    if (!state.rebuilt) exit(1);
    if (state.users.some((u) => u.userName === args[0])) {
      out("A user with the same username already exists.");
      exit(1);
    }
    state.users.push({ id: `admin-${state.users.length}`, userName: args[0], type: "admin", isActive: true });
    out(`The user '${args[0]}' has been created.`);
    exit(0);
  }
  case "set-password": {
    const user = state.users.find((u) => u.userName === args[0]);
    if (!user) {
      out(`User '${args[0]}' not found.`);
      exit(1);
    }
    out("Enter a new password:");
    const password = readFileSync(0, "utf8").split("\n")[0];
    if (!password) {
      out("Password cannot be empty.");
      exit(1);
    }
    user.password = password;
    out(`Password for user '${args[0]}' has been changed.`);
    exit(0);
  }
  case "populate-scheduled-jobs":
  case "clear-cache":
  case "migrate":
    exit(0);
  case "app-check":
    exit(mergedConfig(state).database?.platform === "Postgresql" ? 0 : 1);
  default:
    out(`Command '${command}' does not exist.`);
    exit(1);
}
