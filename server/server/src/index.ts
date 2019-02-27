#!/usr/bin/env node

import * as program from 'commander';
import { DapServer } from './server';

const DEFAULT_PORT = 8888;

let targetProcess = null;
program
  .version('0.1.0')
  .arguments('<target>')
  .action(target => targetProcess = target)
  .option('-n, --numeric', 'Attach by process id instead of name')
  .option('-A, --adb', 'Connect to a device via ADB')
  .option('-p, --port <port>', 'Set the port to listen on', DEFAULT_PORT)
  .parse(process.argv);
targetProcess = program.numeric ? parseInt(targetProcess, 10) : targetProcess;
const dapServer = new DapServer(program.port);
dapServer.start();
if (targetProcess) {
  console.log(`attaching to process ${typeof targetProcess}:${targetProcess}`);
  dapServer.attach(targetProcess, program.adb);
}
