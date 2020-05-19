//import * as express from "express";
//import { EventMatcher } from "../types/event-matcher";

/*
   # API Definition
   POST /typesAssignments/:id

   # Description
   Update a TypeAssignment

   # Path Parameters
   id: Integer        - ID of type assignment

   # Request Body Parameters
   typeId: Integer
   matcher: EventMatcher
 */
/*export const updateTypeAssignment = (
  req: express.Request,
  resp: express.Response
) => {
  const id: number = parseInt(req.params.id, 10);
  const typeId: number = req.body.typeId;
  const matcher: EventMatcher = req.body.matcher;
  this.fridaSession
    .typeAssignUpdate(id, typeId, matcher)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
*/
