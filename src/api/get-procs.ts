import { Request, Response } from "express";
import psList from "ps-list";

export const getProcs = async (_: Request, res: Response): Promise<void> => {
  const data = await psList();
  res.status(200).send(data);
};
