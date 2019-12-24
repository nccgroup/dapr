import * as express from "express";
import psList from "ps-list";
export const getProcs = async (
  _: express.Request,
  resp: express.Response,
  __: express.NextFunction
): Promise<void> => {
  const data = await psList();
  resp.status(200).send(data);
};
