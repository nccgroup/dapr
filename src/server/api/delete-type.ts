import { Request, Response } from "express";
import { types } from "../store/db";
/*
   # API Definition
   POST /types/:id/delete

   # Description
   Delete a type definition

   # Path Parameters
   id: Integer
 */
export const deleteType = (req: Request, res: Response) => {
  const type = types.find({ id: req.params.id });
  types.remove(type);
  res.status(200);
};
