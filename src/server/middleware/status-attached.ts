/*import { Request, Response, NextFunction } from "express";
import { SessionStatus, isStatus } from "./../frida-session";

export const isStatusAttached = (
  _: Request,
  res: Response,
  next: NextFunction
) => {
  const [session, isAttached] = isStatus(SessionStatus.ATTACHED);
  if (session === null || !isAttached) {
    res
      .status(500)
      .send(
        "Currently, not attached to a process. Must be attached to call this API."
      );
    return;
  }

  next();
};
*/
