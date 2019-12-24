import * as express from "express";
import { StructDef } from "../types";
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
export const getType = (req: express.Request, resp: express.Response) => {
  const id = parseInt(req.params.id, 10);
  this.fridaSession
    .typeGet(id)
    .then(res => resp.send(res))
    .catch(e => resp.status(500).send(e.toString()));
};
