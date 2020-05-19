import { Request, Response, NextFunction } from "express";

export const dnsRebinding = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (
    req.headers.host !== `localhost:8888` &&
    req.headers.host !== `127.0.0.1:8888`
  ) {
    res.status(500).end();
    return;
  }

  next();
};
