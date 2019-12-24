import * as express from "express";
import { SessionStatus } from "./../frida_session";

export const statusPending = (
  _: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  if (
    // TODO: fix this
    !!this.fridaSession &&
    this.fridaSession.status === SessionStatus.PENDING
  ) {
    res.status(500).send("Operation pending");
    res.end();
  } else {
    next();
  }
};
