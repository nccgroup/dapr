#!/usr/bin/env node

import * as program from 'commander';
import { DapServer } from './server';

const DEFAULT_PORT = 8888;

let targetProcess = null;
program
  .version('0.1.0')
  .arguments('<target>')
  .option('-A, --adb', 'Connect to a device via ADB')
  .option('-p, --port <port>', 'Set the port to listen on', DEFAULT_PORT)
  .parse(process.argv);
 new DapServer(program.port).start();
