"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const child_process_1 = require("child_process");
const frida = require("frida");
// import * as frida_compile from 'frida-compile';
class FridaHelper {
    constructor(targetProcess, adb) {
        this.isRoot = false;
        this.adb = false;
        this.script = null;
        this.session = null;
        this.device = null;
        this.target = targetProcess;
        this.adb = adb;
    }
    getFD(fd) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.getFD(fd);
        });
    }
    setFD(fd, path) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.setFD(fd, path);
        });
    }
    getFDs() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.getFDs();
        });
    }
    shell(command) {
        if (this.adb) {
            return this.adbShell(command);
        }
        const args = command.length === 1 ? [] : command.slice(1, command.length);
        return child_process_1.spawnSync(command[0], args);
    }
    adbShell(command) {
        const args = ['shell'];
        if (this.isRoot) {
            args.push('su');
            args.push('-c');
        }
        for (const arg in command) {
            args.push(command[arg]);
        }
        return child_process_1.spawnSync('adb', args);
    }
    detectIsRoot() {
        this.isRoot = false;
        const commandResult = this.shell(['id']);
        if (commandResult.status === 0) {
            if (commandResult.output[1].toString().search('uid=0') < 0 &&
                commandResult.output[1].toString().search('(root)') < 0) {
                this.isRoot = true;
            }
        }
    }
    resolveFileDescriptor(fd) {
        let readlinkResult = null;
        const command = ['readlink', `/proc/${this.session.pid}/fd/${fd}`];
        const commandResult = this.shell(command);
        if (commandResult.status === 0 && commandResult.output.length >= 2) {
            readlinkResult = commandResult.output[1].toString().trim();
            return readlinkResult;
        }
        console.log(`readlink error: ${commandResult.error}`);
        return null;
    }
    resolveFileDescriptors() {
        /* TODO: Attempt multiple methods of reading FDs; fall back to less precise method on each failure
         * 1. Use frida-fs to read /proc/self/fd/ (can fail due to read permissions)
         * 2. Push/run a binary that reads /proc/<pid>/fd/ (can fail on writing to filesystem)
         * 3. Use device.spawn() to `ls -l /proc/<pid>/fd/` (can fail if ls -l output not consisten)
         * 4. Use device.spawn() to `ls /proc/<pid>/fd/` and `readlink` each fd
        */
        const files = {};
        const command = ['ls', '-l', `/proc/${this.session.pid}/fd`];
        const lsResult = this.shell(command);
        if (lsResult.status === 0 && lsResult.output.length >= 2) {
            for (const line of lsResult.output[1].toString().split('\r\n')) {
                const matchResult = line.match(/([0-9]+) -> (.*)$/);
                if (!!matchResult) {
                    const fd = matchResult[1];
                    const path = matchResult[2];
                    files[fd] = path;
                    console.log(`fd:${fd} path:${path}`);
                }
            }
        }
        else {
            throw 'failed to list fd directory';
        }
        return files;
    }
    startSession() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                if (this.adb) {
                    frida.getUsbDevice({ timeout: 1000 })
                        .then((device) => {
                        this.device = device;
                        this.device.attach(this.target)
                            .then((session) => {
                            this.session = session;
                            resolve();
                        }).catch(e => reject(e));
                    }).catch(e => reject(e));
                }
                else {
                    frida.attach(this.target)
                        .then((session) => {
                        this.session = session;
                        resolve();
                    }).catch(e => reject(e));
                }
            });
        });
    }
    attachScript(scriptPath, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            // TODO: compile the frida script programmatically
            try {
                /*
                const scriptPath = './frida-scripts/ioctler.js'
                const outPath = './generated/ioctler.js';
                const options = {
                  target: false,
                  bytecode: true,
                  babelify: false,
                  sourcemap: null,
                  compress: false,
                  useAbsolutePaths: false,
                }
                console.log(await frida_compile.build(scriptPath, outPath, options));
                const contents: string = fs.readFileSync('generated/out.js', 'utf8');
                this.script = await session.createScriptFromBytes(contents);
                */
                const scriptContents = fs.readFileSync(scriptPath, 'utf8');
                this.script = yield this.session.createScript(scriptContents);
                this.script.message.connect(callback);
                yield this.script.load();
                this.detectIsRoot();
                const files = this.resolveFileDescriptors();
                yield this.script.exports.initFDs(files);
                yield this.script.exports.installHooks();
            }
            catch (err) {
                console.error(err);
            }
        });
    }
    stop() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!!this.script) {
                this.script.message.disconnect(() => { });
                yield this.script.unload();
                this.script = null;
                console.debug('[frida_helper] unloaded script');
            }
            if (!!this.session) {
                yield this.session.detach();
                this.session = null;
                console.debug('[frida_helper] detached session');
            }
        });
    }
}
exports.FridaHelper = FridaHelper;
//# sourceMappingURL=frida_helper.js.map