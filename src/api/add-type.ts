import * as express from "express";
import { StructDef } from "../types";
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
export const addType = (req: express.Request, resp: express.Response) => {
  const type: StructDef = req.body;
  this.fridaSession
    .typePut(type)
    .then(res => resp.send({ id: res }))
    .catch(e => resp.status(500).send(e.toString()));
};
