import { Request, Response } from "express";
import { getFridaSession, uninstall } from "../frida-session";

/*
   # API Definition
   POST /session/detach

   # Description
   Detach from a Frida session.

   Note: The result of this operation can be checked by polling /session/status.
 */
export const sessionUninstall = async (req: Request, res: Response) => {
  const { pid } = req.body;
  const { user } = req;
  if (!user) {
    res.status(403).send("No user");
    return;
  }
  const installation = getFridaSession(user, pid);
  if (installation === null) {
    res.status(304).end();
    return;
  }
  await uninstall(installation);
  res.status(200).end();
};
