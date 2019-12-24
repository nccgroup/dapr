import * as express from "express";
import { EventMatcher } from "../types/event-matcher";
/*
   # API Definition
   POST /typesAssignments

   # Description
   Assign a TypeDef to an EventMatcher.

   # Request Body Parameters
   typeId: Integer
   matcher: EventMatcher

   # Response Body
   id: Integer        - ID of type assignment
 */
export const addTypedefToTypeAssignment = (
  req: express.Request,
  resp: express.Response
) => {
  const typeId: number = req.body.typeId;
  const matcher: EventMatcher = req.body.matcher;
  this.fridaSession
    .typeAssignPut(typeId, matcher)
    .then(res => resp.send({ id: res }))
    .catch(e => resp.status(500).send(e.toString()));
};
