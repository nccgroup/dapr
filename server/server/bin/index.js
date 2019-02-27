#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const program = require("commander");
const server_1 = require("./server");
let targetProcess = null;
program
    .version('0.1.0')
    .arguments('<target>')
    .action(target => targetProcess = target)
    .option('-n, --numeric', 'Attach by process id instead of name')
    .option('-A, --adb', 'Connect to a device via ADB')
    .parse(process.argv);
if (targetProcess) {
    targetProcess = program.numeric ? parseInt(targetProcess, 10) : targetProcess;
    console.log(program);
    console.log(`attaching to process ${typeof targetProcess}:${targetProcess}`);
    const dapServer = new server_1.DapServer();
    dapServer.start();
    dapServer.attach(targetProcess, program.adb)
        .catch((e) => {
        dapServer.stop();
        console.error(e);
    });
}
//# sourceMappingURL=index.js.map