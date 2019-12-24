import * as express from "express";

/*
   # API Definition
   POST /typesAssignments/:id/delete

   # Description
   Delete a TypeAssignment

   # Path Parameters
   id: Integer        - ID of type assignment
 */
export const deleteTypeAssignment = (
  req: express.Request,
  resp: express.Response
) => {
  const id = parseInt(req.params.id, 10);
  this.fridaSession
    .typeDelete(id)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
