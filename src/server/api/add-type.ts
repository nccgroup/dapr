import { Request, Response } from "express";
import { types } from "../store/db";
/*
   # API Definition
   POST /types

   # Description
   Define a new type

   # Request Body Parameters
   TypeDef

   # Response Body
   id: Integer
 */
export const addType = (req: Request, res: Response) => {
  types.insert(req.body);
  res.status(200);
};
