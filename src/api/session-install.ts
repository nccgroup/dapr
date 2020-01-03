import { Request, Response } from "express";
import { install } from "../frida-session";
import { events } from "../store/db";
import { ScriptMessageHandler, Message, MessageType } from "frida/dist/script";
import { memoResolveFileDescriptor } from "../../shared/util/procs";
import { defaultTo } from "lodash";
import { Syscall } from "../../shared/types/syscalls";
/*
   # API Definition
   POST /session/attach

   # Description
   Asynchronously attaches Frida to a `target` process, which can be either a process ID or process name. On success,
   Dapr begins hooking system calls and streams events to websocket clients.

   Note: The result of this operation can be checked by polling /session/status.

   target: Integer | String      - process ID or process name
 */
export const sessionInstall = async (req: Request, res: Response) => {
  const { pid, adb } = req.body;
  const session = await install(
    req.user,
    pid,
    adb,
    onFridaMessage(pid, adb),
    onFridaAttach
  );

  if (session === null) {
    res.status(500).end();
    return;
  }
  res.status(200).end();
};

const onFridaAttach = () => {};

// onFridaMessage is the default handler for logging events from
// frida script hooks. Currently, it logs them in a database.
const onFridaMessage = (pid: number, adb: boolean): ScriptMessageHandler => (
  message: Message,
  data: Buffer | null
): void => {
  switch (message.type) {
    case MessageType.Send:
      let event: Syscall = Object.assign(
        {},
        { type: message.type, ...message.payload }
      );
      if (data !== null) {
        event = Object.assign({}, event, { data: data.toJSON() });
      }

      event = Object.assign({}, event, {
        pid: pid,
        driverName: defaultTo(
          memoResolveFileDescriptor(pid, event.fd, adb),
          `<unknown:${event.fd}>`
        )
      });

      events.insert(event);
      break;
    case MessageType.Error:
      console.error("Error from frida script", message);
      break;
    default:
      console.log("default", message, data);
  }
};
