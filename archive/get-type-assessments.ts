import * as express from "express";
/*
   # API Definition
   GET /typesAssignments

   # Description
   Get all type assignments.

   Note: The purpose of type assignments is to associate a TypeDef with an EventMatcher. For each Event that matches
   the criteria of the EventMatcher, Dapr applies special attributes of the TypeDef, which may alter how Dapr
   handles the event.

   # Response Body
   [TypeAssignment, ...]

   # Types
   TypeAssignment:
   matcher: Matcher
   typeId: Integer
 */
export const getTypeAssessments = (
  _: express.Request,
  resp: express.Response
) => {
  this.fridaSession
    .typeAssignGetAll()
    .then(result => resp.send(result))
    .catch(e => resp.status(500).send(e.toString()));
};
