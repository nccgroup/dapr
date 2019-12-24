#!/usr/bin/env node

import * as program from "commander";
import { app, quit } from "./server";
import * as process from "process";
const DEFAULT_PORT = 8888;

program
  .version("0.1.0")
  .arguments("<target>")
  .option("-A, --adb", "Connect to a device via ADB")
  .option("-p, --port <port>", "Set the port to listen on", DEFAULT_PORT)
  .parse(process.argv);

const server = app.listen(program.port, () =>
  console.log(`started on port ${program.port}`)
);
process.on("SIGTERM", () => quit(server));
process.on("SIGINT", () => quit(server));
