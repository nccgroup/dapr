"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const child_process_1 = require("child_process");
const frida = require("frida");
// import * as frida_compile from 'frida-compile';
var SessionStatus;
(function (SessionStatus) {
    SessionStatus[SessionStatus["DETACHED"] = 0] = "DETACHED";
    SessionStatus[SessionStatus["ATTACHED"] = 1] = "ATTACHED";
    SessionStatus[SessionStatus["PENDING"] = 2] = "PENDING";
    SessionStatus[SessionStatus["FAILED"] = 3] = "FAILED";
})(SessionStatus = exports.SessionStatus || (exports.SessionStatus = {}));
class FridaSession {
    constructor(targetProcess, adb) {
        this.isRoot = false;
        this.adb = false;
        this.status = SessionStatus.DETACHED;
        this.reason = null;
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
    attach(callback, onAttach) {
        this.status = SessionStatus.PENDING;
        if (this.adb) {
            frida.getUsbDevice({ timeout: 1000 })
                .then((device) => {
                this.device = device;
                this.device.attach(this.target)
                    .then((session) => __awaiter(this, void 0, void 0, function* () {
                    this.session = session;
                    this.loadScript(callback, onAttach);
                })).catch((e) => {
                    this.fail(e);
                });
            }).catch((e) => {
                this.fail(e);
            });
        }
        else {
            frida.attach(this.target)
                .then((session) => __awaiter(this, void 0, void 0, function* () {
                this.session = session;
                this.loadScript(callback, onAttach);
            })).catch((e) => {
                this.fail(e);
            });
        }
    }
    detach() {
        if (!this.session) {
            this.status = SessionStatus.DETACHED;
            if (!!this.script) {
                throw new Error('Bad state');
            }
        }
        else {
            this.status = SessionStatus.PENDING;
            this.script.message.disconnect(() => { });
            this.script.unload()
                .then(() => {
                this.script = null;
                console.debug('[FridaSession] unloaded script');
                if (!!this.session) {
                    this.session.detach()
                        .then(() => {
                        this.session = null;
                        this.status = SessionStatus.DETACHED;
                        console.debug('[FridaSession] detached session');
                    })
                        .catch((e) => {
                        this.fail(e);
                    });
                }
            })
                .catch((e) => {
                this.fail(e);
            });
        }
    }
    inject(syscalls) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.inject(syscalls);
        });
    }
    blacklistGetAll() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.blacklistGetAll();
        });
    }
    blacklistGet(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.blacklistGet(index);
        });
    }
    blacklistPut(matcher) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.blacklistPut(matcher);
        });
    }
    blacklistUpdate(index, matcher) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.blacklistUpdate(index, matcher);
        });
    }
    blacklistDelete(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.blacklistDelete(index);
        });
    }
    typeGetAll() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeGetAll();
        });
    }
    typeGet(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeGet(index);
        });
    }
    typePut(type) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typePut(type);
        });
    }
    typeUpdate(index, type) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeUpdate(index, type);
        });
    }
    typeDelete(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeDelete(index);
        });
    }
    typeAssignGetAll() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeAssignGetAll();
        });
    }
    typeAssignGet(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeAssignGet(index);
        });
    }
    typeAssignPut(typeId, matcher) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeAssignPut(typeId, matcher);
        });
    }
    typeAssignUpdate(index, typeId, matcher) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeAssignUpdate(index, typeId, matcher);
        });
    }
    typeAssignDelete(index) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.script.exports.typeAssignDelete(index);
        });
    }
    loadScript(callback, onAttach) {
        // await this.session.enableJit();
        const scriptPath = './bin/ioctler.js';
        let scriptContents;
        try {
            scriptContents = fs.readFileSync(scriptPath, 'utf8');
            this.session.createScript(scriptContents)
                .then((script) => {
                this.script = script;
                script.message.connect(callback);
                script.load()
                    .then(() => {
                    this.detectIsRoot();
                    const files = this.resolveFileDescriptors();
                    script.exports.init(files)
                        .then(() => {
                        this.status = SessionStatus.ATTACHED;
                        onAttach();
                    })
                        .catch((e) => {
                        this.fail(e);
                    });
                });
            })
                .catch((e) => {
                this.fail(e);
            });
        }
        catch (e) {
            this.fail(e);
        }
    }
    fail(e) {
        this.status = SessionStatus.FAILED;
        this.reason = e;
        console.error(e.stack.toString());
    }
}
exports.FridaSession = FridaSession;
//# sourceMappingURL=frida_session.js.map