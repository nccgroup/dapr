import * as fs from 'fs';
import { spawnSync, SpawnSyncReturns } from 'child_process';
import * as frida from 'frida';
import { Session } from 'frida/dist/session';
import { Script, ScriptMessageHandler } from 'frida/dist/script';
import { Device } from 'frida/dist/device';
import { Syscall } from './types/syscalls';
import { EventMatcher } from './types/event-matcher';
import { StructDef } from './types';
// import * as frida_compile from 'frida-compile';

export enum SessionStatus {
  DETACHED,
  ATTACHED,
  PENDING,
  FAILED,
}

export class FridaSession {
  private isRoot: boolean = false;
  private adb: boolean = false;
  private target: string|number;
  public status: SessionStatus = SessionStatus.DETACHED;
  public reason: Error = null;
  public script: Script = null;
  public session: Session = null;
  public device: Device = null;
  constructor(targetProcess : string|number, adb: boolean) {
    this.target = targetProcess;
    this.adb = adb;
  }
  async getFD(fd: number) : Promise<string|void> {
    return await this.script.exports.getFD(fd);
  }
  async setFD(fd: number, path: string) {
    return await this.script.exports.setFD(fd, path);
  }
  async getFDs() {
    return await this.script.exports.getFDs();
  }
  shell(command: string[]) : SpawnSyncReturns<string|Buffer>  {
    if (this.adb) {
      return this.adbShell(command);
    }
    const args = command.length === 1 ? [] : command.slice(1, command.length);
    return spawnSync(command[0], args);
  }
  adbShell(command: string[]) : SpawnSyncReturns<string|Buffer>  {
    const args = ['shell'];
    if (this.isRoot) {
      args.push('su');
      args.push('-c');
    }
    for (const arg in command) {
      args.push(command[arg]);
    }
    return spawnSync('adb', args);
  }
  private detectIsRoot() : void {
    this.isRoot = false;
    const commandResult = this.shell(['id']);
    if (commandResult.status === 0) {
      if (commandResult.output[1].toString().search('uid=0') < 0 &&
          commandResult.output[1].toString().search('(root)') < 0) {
        this.isRoot = true;
      }
    }
  }
  resolveFileDescriptor(fd: number) : string {
    let readlinkResult: string = null;
    const command = ['readlink', `/proc/${this.session.pid}/fd/${fd}`];
    const commandResult = this.shell(command);
    if (commandResult.status === 0 && commandResult.output.length >= 2) {
      readlinkResult = commandResult.output[1].toString().trim();
      return readlinkResult;
    }
    console.log(`readlink error: ${commandResult.error}`);
    return null;
  }
  resolveFileDescriptors() : object {
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
    } else {
      throw 'failed to list fd directory';
    }
    return files;
  }
  attach(callback, onAttach) : void {
    this.status = SessionStatus.PENDING;
    if (this.adb) {
      frida.getUsbDevice({ timeout: 1000 })
          .then((device) => {
            this.device = device;
            this.device.attach(this.target)
                .then(async (session) => {
                  this.session = session;
                  this.loadScript(callback, onAttach);
                }).catch((e) => {
                  this.fail(e);
                });
          }).catch((e) => {
            this.fail(e);
          });
    } else {
      frida.attach(this.target)
          .then(async (session) => {
            this.session = session;
            this.loadScript(callback, onAttach);
          }).catch((e) => {
            this.fail(e);
          });
    }
  }
  detach() : void {
    if (!this.session) {
      this.status = SessionStatus.DETACHED;
      if (!!this.script) {
        throw new Error('Bad state');
      }
    } else {
      this.status = SessionStatus.PENDING;
      this.script.message.disconnect(() => {});
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
  async inject(syscalls: Syscall[]) {
    return await this.script.exports.inject(syscalls);
  }
  async blacklistGetAll() {
    return await this.script.exports.blacklistGetAll();
  }
  async blacklistGet(index: number) {
    return await this.script.exports.blacklistGet(index);
  }
  async blacklistPut(matcher: EventMatcher) {
    return await this.script.exports.blacklistPut(matcher);
  }
  async blacklistUpdate(index: number, matcher: EventMatcher) {
    return await this.script.exports.blacklistUpdate(index, matcher);
  }
  async blacklistDelete(index: number) {
    return await this.script.exports.blacklistDelete(index);
  }

  async typeGetAll() {
    return await this.script.exports.typeGetAll();
  }
  async typeGet(index: number) {
    return await this.script.exports.typeGet(index);
  }
  async typePut(type: StructDef) {
    return await this.script.exports.typePut(type);
  }
  async typeUpdate(index: number, type: StructDef) {
    return await this.script.exports.typeUpdate(index, type);
  }
  async typeDelete(index: number) {
    return await this.script.exports.typeDelete(index);
  }

  async typeAssignGetAll() {
    return await this.script.exports.typeAssignGetAll();
  }
  async typeAssignGet(index: number) {
    return await this.script.exports.typeAssignGet(index);
  }
  async typeAssignPut(typeId: number, matcher: EventMatcher) {
    return await this.script.exports.typeAssignPut(typeId, matcher);
  }
  async typeAssignUpdate(index: number, typeId: number, matcher: EventMatcher) {
    return await this.script.exports.typeAssignUpdate(index, typeId, matcher);
  }
  async typeAssignDelete(index: number) {
    return await this.script.exports.typeAssignDelete(index);
  }

  private loadScript(callback: ScriptMessageHandler, onAttach) : void {
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
    } catch (e) {
      this.fail(e);
    }
  }
  private fail(e: Error) {
    this.status = SessionStatus.FAILED;
    this.reason = e;
    console.error(e.stack.toString());
  }
}
