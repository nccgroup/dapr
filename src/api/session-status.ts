//import { Request, Response } from "express";
//import { SessionStatus, getFridaSession } from "./../frida-session";

/*
   # API Definition
   GET /session/status

   # Description
   Returns the current state of the Frida session. Poll this API after doing an `attach` or `detach`. When the status
   is "attached", the process ID is also returned.

   # Request Body Parameters
   N/A

   # Response Body
   status: string
   pid: Integer or Undefined
*/
/*
interface Status {
  status: string;
  pid?: number;
  reason?: string;
}
export const sessionStatus = (_: Request, res: Response) => {
  let out: Status;
  const session = getFridaSession();
  if (session === null) {
    out.status = "detached";
  } else {
    switch (session.status) {
      case SessionStatus.ATTACHED:
        out.status = "attached";
        out.pid = session.session.pid;
        break;
      case SessionStatus.FAILED:
        out.status = "failed";
        out.reason = session.reason.message.toString();
        break;
      case SessionStatus.PENDING:
        out.status = "pending";
        break;
      case SessionStatus.DETACHED:
        out.status = "detached";
        break;
      default:
        out.status = "unknown status";
    }
  }
  res.send(out);
};
*/
