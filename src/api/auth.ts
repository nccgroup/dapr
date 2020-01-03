import { Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import { memoize } from "lodash";
import * as fs from "fs";
const getSecretKey = async (): Promise<jwt.Secret | null> =>
  await new Promise((res, rej) =>
    fs.readFile("private.pem", (err: NodeJS.ErrnoException, data: Buffer) => {
      if (err !== null) {
        rej(err);
        return;
      }
      res(data);
    })
  );

const memoGetSecretKey = memoize(getSecretKey);
export const authenticate = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (username === "root" && password === "root") {
    const secret = await memoGetSecretKey();
    if (secret === null) {
      res.status(500).end();
      return;
    }
    res.cookie(
      "X-DAPR-Token",
      jwt.sign({ name: "root" }, secret, { expiresIn: "7d" })
    );
  }
  res.status(200).end();
};
