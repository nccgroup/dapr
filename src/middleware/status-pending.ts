import { Request, Response, NextFunction } from "express";
import { isStatus, SessionStatus } from "../frida-session";

export const isStatusPending = (
  _: Request,
  res: Response,
  next: NextFunction
) => {
  const [session, isPending] = isStatus(SessionStatus.PENDING);
  if (session === null || isPending) {
    res
      .status(500)
      .send(
        session === null
          ? "There is no session"
          : "Operation currently pending. Wait until the operation is finished before calling this API again."
      );
    return;
  }

  next();
};
