import { Request, Response, NextFunction } from "express";
import * as jwt from "jsonwebtoken";
import { memoize } from "lodash";
import { User } from "../../shared/types/user";
import * as fs from "fs";
import { pubKey } from "../../shared/util/keys";
import { daprTokenName } from "../../shared/util/token";

const getPubKey = async (): Promise<Buffer> =>
  await new Promise(res =>
    fs.readFile(pubKey, (err: NodeJS.ErrnoException, data: Buffer) => {
      if (err !== null) {
        res(null);
        return;
      }
      res(data);
    })
  );
const memoGetPubKey = memoize(getPubKey);

declare module "express" {
  interface Request {
    user?: User;
  }
}

export const isAuthenticated = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const dapr = req.get(daprTokenName);
  if (!dapr) {
    res.status(403).end();
    return;
  }

  const cert = await memoGetPubKey();
  if (cert === null) {
    res.status(500).end();
    return;
  }
  const user: User = await new Promise(res => {
    jwt.verify(dapr, cert, (err: jwt.VerifyErrors, decoded: User) => {
      if (err !== null) {
        console.error(err);
        res(null);
      }
      res(decoded);
    });
  });
  console.log("user", user);

  if (user === null) {
    res.status(403).end();
    return;
  }
  req.user = user;
  next();
};
