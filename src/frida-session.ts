import * as fs from "fs";
import * as frida from "frida";
import { Session } from "frida/dist/session";
import { Script, ScriptMessageHandler } from "frida/dist/script";
import { defaultTo, memoize } from "lodash";
import { User } from "../shared/types/user";

interface Installation {
  session: Session;
  script: Script;
}

const sessions: { [key: string]: Installation } = {};

export const getFridaSessions = (): Installation[] => Object.values(sessions);

// getFridaSession returns the frida session associated with the user and pid.
export const getFridaSession = (user: User, pid: number): Installation | null =>
  defaultTo(sessions[`${user.name}:${pid}`], null);

// getFridaScript reads the contents of the frida script
// and returns it as a string.
const getFridaScript = async (): Promise<string | null> => {
  const scriptPath = "./bin/ioctler.js";
  return await new Promise(res =>
    fs.readFile(
      scriptPath,
      "utf8",
      (err: NodeJS.ErrnoException | null, data: string) => {
        if (err !== null) {
          res(null);
        }
        res(data);
      }
    )
  );
};

// loadScript creates the RPC script that is used to collect
// information about the process syscalls.
const loadScript = async (
  session: Session,
  callback: ScriptMessageHandler,
  onAttach: Function
): Promise<Script | null> => {
  const scriptContents = await memoGetFridaScript();
  if (scriptContents === null) {
    return null;
  }
  const script = await session.createScript(scriptContents);
  script.message.connect(callback);
  await script.load();
  await script.exports.hook();
  onAttach();
  return script;
};

// install attaches to the ADB device or the local machine, loads
// the frida script, and returns both the session and script if
// successfull.
export const install = async (
  user: User,
  pid: number,
  adb: boolean,
  onMessage: ScriptMessageHandler,
  onAttach: Function
): Promise<Installation | null> => {
  let device: { attach(pid: number): Promise<Session> } = frida;
  if (adb) {
    device = await frida.getUsbDevice({ timeout: 1000 });
  }
  const session = await attach(device, pid);
  if (session === null) {
    return null;
  }
  const script = await loadScript(session, onMessage, onAttach);
  if (script === null) {
    return null;
  }

  const installation = { session: session, script: script };
  sessions[`${user.name}:${pid}`] = installation;
  return installation;
};

const attach = async (
  device: { attach(pid: number): Promise<Session> },
  pid: number
): Promise<Session | null> => {
  try {
    return await device.attach(pid);
  } catch (e) {
    console.error("Error attaching: ", e);
  }
  return null;
};

// uninstall disconnects a scripts session, unloads its
// and detaches the session.
export const uninstall = async (installation: Installation): Promise<void> => {
  try {
    installation.script.message.disconnect(() => {});
  } catch (e) {
    console.error("Error disconnecting script", e);
  }

  try {
    await installation.script.unload();
  } catch (e) {
    console.error("Error unloading script", e);
  }

  try {
    await installation.session.detach();
  } catch (e) {
    console.error("Error detaching session", e);
  }
};

const memoGetFridaScript = memoize(getFridaScript);
