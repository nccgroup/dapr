import * as express from "express";
import { StructDef } from "../types";

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
  const id = parseInt(req.params.id, 10);
  const type: StructDef = req.body;
  this.fridaSession
    .typeUpdate(id, type)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
