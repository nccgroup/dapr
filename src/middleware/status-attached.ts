import * as express from "express";
import { SessionStatus } from "./../frida_session";

export const statusAttached = (
  _: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  //TODO: fix this
  if (
    !this.fridaSession ||
    this.fridaSession.status !== SessionStatus.ATTACHED
  ) {
    res.status(500).send("Must be attached");
    res.end();
  } else {
    next();
  }
};
