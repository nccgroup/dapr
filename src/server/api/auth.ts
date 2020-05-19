import { Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import { memoize } from "lodash";
import * as fs from "fs";
import { privKey } from "../../shared/util/keys";
const getSecretKey = async (): Promise<jwt.Secret | null> =>
  await new Promise(res =>
    fs.readFile(privKey, (err: NodeJS.ErrnoException | null, data: Buffer) => {
      if (err !== null) {
        res(null);
        return;
      }
      res(data);
    })
  );

const memoGetSecretKey = memoize(getSecretKey);
export const authenticate = async (req: Request, res: Response) => {
  const { password } = req.body;
  if (password !== "root") {
    res.status(403).end();
    return;
  }

  const secret = await memoGetSecretKey();
  if (secret === null) {
    res.status(500).end();
    return;
  }
  res
    .type("json")
    .status(200)
    .send(
      JSON.stringify({
        token: jwt.sign({ name: "root" }, secret, {
          algorithm: "RS256",
          expiresIn: "7d"
        })
      })
    );
};
