import { Request, Response, NextFunction } from "express";
import * as jwt from "jsonwebtoken";
import { memoize } from "lodash";
import { User } from "../../shared/types/user";
import * as fs from "fs";
const getPubKey = async (): Promise<Buffer> =>
  await new Promise((res, rej) =>
    fs.readFile("public.pem", (err: NodeJS.ErrnoException, data: Buffer) => {
      if (err !== null) {
        rej(err);
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
  const { token } = req.body;

  const cert = await memoGetPubKey();
  const user: User = await new Promise(res => {
    jwt.verify(token, cert, (err: jwt.VerifyErrors, decoded: User) => {
      if (err !== null) {
        console.error(err.message);
        res(null);
      }
      res(decoded);
    });
  });

  if (user === null) {
    req.cookies.set("X-DAPR-Token", { maxAge: Date.now() });
    res.redirect("/");
    return;
  }
  req.user = user;
  next();
};
