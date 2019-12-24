import * as express from "express";

export const dnsRebinding = (
  req: express.Request,
  _: express.Response,
  next: express.NextFunction
) => {
  if (
    req.headers.host !== `localhost:${this.port}` &&
    req.headers.host !== `127.0.0.1:${this.port}`
  ) {
    next("DNS rebinding attack blocked");
  } else {
    next();
  }
};
