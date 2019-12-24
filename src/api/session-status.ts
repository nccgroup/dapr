import * as express from "express";
import { SessionStatus } from "./../frida-session";

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
export const sessionStatus = (req: express.Request, res: express.Response) => {
  const out: any = {};
  //TODO: fix this
  if (!this.fridaSession) {
    out.status = "detached";
  } else {
    switch (this.fridaSession.status) {
      case SessionStatus.ATTACHED:
        out.status = "attached";
        out.pid = this.fridaSession.session.pid;
        break;
      case SessionStatus.FAILED:
        out.status = "failed";
        out.reason = this.fridaSession.reason.message.toString();
        break;
      case SessionStatus.PENDING:
        out.status = "pending";
        break;
      case SessionStatus.DETACHED:
        out.status = "detached";
        break;
      default:
        throw new Error("unknown status");
    }
  }
  res.send(out);
};
