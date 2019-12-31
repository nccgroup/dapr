import * as express from "express";
import { types } from "../store/db";
/*
   # API Definition
   POST /types/:id

   # Description
   Update a type definition

   # Path Parameters
   id: Integer

   # Request Body Parameters
   TypeDef
 */
export const updateType = (req: express.Request, resp: express.Response) => {
  let type = types.find({ id: req.params.id });
  type = req.body;
  types.update(type);
};
