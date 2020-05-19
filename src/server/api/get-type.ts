import { Request, Response } from "express";
import { types } from "../store/db";

/*
   # API Definition
   GET /types/:id

   # Description
   Get a type at a specified index.

   # Path Parameters
   id: Integer

   # Response Body
   TypeDef
 */
export const getType = (req: Request, res: Response) => {
  res.send(types.find({ id: req.params.id }));
};
