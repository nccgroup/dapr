import * as fs from "fs";
import { spawnSync, SpawnSyncReturns } from "child_process";
import * as frida from "frida";
import { Session } from "frida/dist/session";
import { Script, ScriptMessageHandler, Message } from "frida/dist/script";
import { Device } from "frida/dist/device";
import { Syscall } from "./types/syscalls";
import { events } from "./store/db";
import { IoctlResponse } from "./frida-scripts/send-ioctl";

export enum SessionStatus {
  DETACHED,
  ATTACHED,
  PENDING,
  FAILED
}

let session: FridaSession;
export const isStatus = (
  status: SessionStatus
): [FridaSession | null, boolean] => {
  const session = getFridaSession();
  if (session === null) {
    return [null, false];
  } else if (session.status === status) {
    return [session, true];
  }

  return [session, false];
};

export const getFridaSession = (): FridaSession | null => {
  return session;
};

export const newFridaSession = (
  target: string | number,
  adb: boolean
): FridaSession => {
  const [s, detached] = isStatus(SessionStatus.DETACHED);
  if (s !== null && !detached) {
    s.detach();
  }
  session = new FridaSession(target, adb);
  return session;
};

export const onFridaAttach = () => {};

export const onFridaMessage = (message: Message, data: Buffer): void => {
  if (message.type === "send") {
    if (message.payload.syscall !== "ioctl") {
      return;
    }

    if (!!data) {
      message.payload.data = JSON.parse(JSON.stringify(data)).data;
    }
    if (!message.payload.driverName) {
      message.payload.driverName = `<unknown:${message.payload.fd}>`;
    }
    events.add(message.payload);
  } else if (message.type === "error") {
    console.log("error", JSON.stringify(message));
  } else {
    console.log("unknown message", JSON.stringify(message));
  }
};

class FridaSession {
  private isRoot: boolean;
  private adb: boolean;
  private target: string | number;
  public status: SessionStatus;
  public reason: Error | null;
  public script: Script | null;
  public session: Session | null;
  public device: Device | null;
  constructor(targetProcess: string | number, adb: boolean) {
    this.isRoot = false;
    this.status = SessionStatus.DETACHED;
    this.reason = null;
    this.script = null;
    this.session = null;
    this.device = null;
    this.target = targetProcess;
    this.adb = adb;
  }
  async getFD(fd: number): Promise<string | null> {
    if (this.script === null) {
      return null;
    }
    return await this.script.exports.getFD(fd);
  }
  async setFD(fd: number, path: string): Promise<void> {
    if (this.script === null) {
      return;
    }
    return await this.script.exports.setFD(fd, path);
  }
  async getFDs(): Promise<{ [key: string]: string } | null> {
    if (this.script === null) {
      return null;
    }
    return await this.script.exports.getFDs();
  }
  shell(command: string[]): SpawnSyncReturns<string | Buffer> {
    if (this.adb) {
      return this.adbShell(command);
    }
    const args = command.length === 1 ? [] : command.slice(1, command.length);
    return spawnSync(command[0], args);
  }
  adbShell(command: string[]): SpawnSyncReturns<string | Buffer> {
    const args = ["shell"];
    if (this.isRoot) {
      args.push("su");
      args.push("-c");
    }
    for (const arg in command) {
      args.push(command[arg]);
    }
    return spawnSync("adb", args);
  }
  private detectIsRoot(): void {
    this.isRoot = false;
    const commandResult = this.shell(["id"]);
    if (commandResult.status === 0) {
      if (
        commandResult.output[1].toString().search("uid=0") < 0 &&
        commandResult.output[1].toString().search("(root)") < 0
      ) {
        this.isRoot = true;
      }
    }
  }
  resolveFileDescriptor(fd: number): string | null {
    if (this.session === null) {
      return null;
    }
    let readlinkResult: string;
    const command = ["readlink", `/proc/${this.session.pid}/fd/${fd}`];
    const commandResult = this.shell(command);
    if (commandResult.status === 0 && commandResult.output.length >= 2) {
      readlinkResult = commandResult.output[1].toString().trim();
      return readlinkResult;
    }
    console.log(`readlink error: ${commandResult.error}`);
    return null;
  }
  resolveFileDescriptors(): {} | null {
    /* TODO: Attempt multiple methods of reading FDs; fall back to less precise method on each failure
     * 1. Use frida-fs to read /proc/self/fd/ (can fail due to read permissions)
     * 2. Push/run a binary that reads /proc/<pid>/fd/ (can fail on writing to filesystem)
     * 3. Use device.spawn() to `ls -l /proc/<pid>/fd/` (can fail if ls -l output not consisten)
     * 4. Use device.spawn() to `ls /proc/<pid>/fd/` and `readlink` each fd
    */
    if (this.session === null) {
      return null;
    }
    const files: { [key: string]: string } = {};
    const command = ["ls", "-l", `/proc/${this.session.pid}/fd`];
    const lsResult = this.shell(command);
    if (lsResult.status === 0 && lsResult.output.length >= 2) {
      for (const line of lsResult.output[1].toString().split("\r\n")) {
        const matchResult = line.match(/([0-9]+) -> (.*)$/);
        if (!!matchResult) {
          const fd = matchResult[1];
          const path = matchResult[2];
          files[fd] = path;
          console.log(`fd:${fd} path:${path}`);
        }
      }
    } else {
      throw "failed to list fd directory";
    }
    return files;
  }
  async attach(
    callback: ScriptMessageHandler,
    onAttach: Function
  ): Promise<void> {
    this.status = SessionStatus.PENDING;
    if (this.adb) {
      try {
        const device = await frida.getUsbDevice({ timeout: 1000 });
        this.device = device;
        try {
          const session = await this.device.attach(this.target);
          this.session = session;
          this.loadScript(callback, onAttach);
        } catch (e) {
          this.fail(e);
        }
      } catch (e) {
        this.fail(e);
      }
    } else {
      try {
        const session = await frida.attach(this.target);
        this.session = session;
        this.loadScript(callback, onAttach);
      } catch (e) {
        this.fail(e);
      }
    }
  }
  async detach(): Promise<void> {
    if (this.session === null) {
      this.status = SessionStatus.DETACHED;
      if (!!this.script) {
        throw new Error("Bad state");
      }
      return;
    }
    this.status = SessionStatus.PENDING;
    if (this.script === null) {
      return;
    }
    this.script.message.disconnect(() => {});
    try {
      await this.script.unload();
      this.script = null;
      console.debug("[FridaSession] unloaded script");
      if (!!this.session) {
        try {
          await this.session.detach();
          this.session = null;
          this.status = SessionStatus.DETACHED;
          console.debug("[FridaSession] detached session");
        } catch (e) {
          this.fail(e);
        }
      }
    } catch (e) {
      this.fail(e);
    }
  }
  async send(syscalls: Syscall[]): Promise<IoctlResponse[] | null> {
    if (this.script === null) {
      return null;
    }

    return await this.script.exports.send(syscalls);
  }

  private async loadScript(
    callback: ScriptMessageHandler,
    onAttach: Function
  ): Promise<void> {
    if (this.session === null) {
      return;
    }

    const scriptPath = "./bin/ioctler.js";
    let scriptContents;
    try {
      scriptContents = fs.readFileSync(scriptPath, "utf8");
      try {
        const script = await this.session.createScript(scriptContents);
        this.script = script;
        script.message.connect(callback);
        await script.load();
        this.detectIsRoot();
        const files = this.resolveFileDescriptors();
        if (files === null) {
          return;
        }
        try {
          await script.exports.init(files);
          this.status = SessionStatus.ATTACHED;
          onAttach();
        } catch (e) {
          this.fail(e);
        }
      } catch (e) {
        this.fail(e);
      }
    } catch (e) {
      this.fail(e);
    }
  }
  private fail(e: Error) {
    this.status = SessionStatus.FAILED;
    this.reason = e;
    if (!e.stack) {
      return;
    }

    console.error(e.stack.toString());
  }
}
