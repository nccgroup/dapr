import { Request, Response } from "express";
import * as _ from "lodash";
import {
  isStatus,
  newFridaSession,
  SessionStatus,
  onFridaMessage,
  onFridaAttach
} from "../frida-session";
/*
   # API Definition
   POST /session/attach

   # Description
   Asynchronously attaches Frida to a `target` process, which can be either a process ID or process name. On success,
   Dapr begins hooking system calls and streams events to websocket clients.

   Note: The result of this operation can be checked by polling /session/status.

   target: Integer | String      - process ID or process name
 */
export const sessionAttach = (req: Request, res: Response) => {
  let { target, adb } = req.body;
  let [session, isAttached] = isStatus(SessionStatus.ATTACHED);
  if (session === null) {
    session = newFridaSession(target, adb);
  } else if (isAttached) {
    res.status(500).send(`Already attached to ${target}`);
    return;
  }
  session.attach(onFridaMessage, onFridaAttach);
  res.status(200).end();
};
