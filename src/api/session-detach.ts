import { Request, Response } from "express";
import { isStatus, SessionStatus } from "../frida-session";
/*
   # API Definition
   POST /session/detach

   # Description
   Detach from a Frida session.

   Note: The result of this operation can be checked by polling /session/status.
 */
export const sessionDetach = (_: Request, res: Response) => {
  const [session, detached] = isStatus(SessionStatus.DETACHED);
  if (session === null || detached) {
    res.status(304).end();
    return;
  }

  if (!detached) {
    session.detach();
  }
  res.status(200).end();
};
