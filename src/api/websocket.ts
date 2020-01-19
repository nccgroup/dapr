import { Request } from "express";
import { setWebSocket } from "../websocket";
import * as ws from "ws";
import { Syscall, SyscallType } from "../../shared/types/syscalls";
/*
   # API Definition
   Websocket Event Stream

   # Description
   If a session is attached, the server streams an array of the most recent events every second.

   # Response Body
   [Event, ...]

   # Types
   Event:
   id: Integer             - Incremental ID of the event
   syscall: String         - Only "ioctl" for now
   fd: Integer             - file descriptor
   driverName: String      - e.g. "/dev/binder"
   mode: String            - "mode" field encoded within of ioctl `request` argument
   size: Integer           - "size" field encoded within of ioctl `request` argument
   opcode: Integer         - "opcode" field encoded within of ioctl `request` argument
   request: String         - The second argument `request` argument of the ioctl syscall
   data: null | Integer[]  - Byte-array of request data, i.e. the third argument of the ioctl syscall
   retval: Integer         - Return value of the ioctl syscall
   start: Integer          - Timestamp of when the ioctl request started
   end: Integer            - Timestamp of when the ioctl request finished
 */

export const wsHandler = (ws: ws, _: Request) => {
  const websocket = setWebSocket(ws);
  websocket.on("message", (data: ws.Data) => {
    const event: Syscall = Object.assign(
      {
        type: "",
        syscall: SyscallType.IOCTL,
        fd: 0,
        request: 0,
        data: new ArrayBuffer(0)
      },
      data
    );
  });
};
