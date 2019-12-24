import * as express from "express";
/*
   # API Definition
   POST /types/:id/delete

   # Description
   Delete a type definition

   # Path Parameters
   id: Integer
 */
export const deleteType = (req: express.Request, resp: express.Response) => {
  const id = parseInt(req.params.id, 10);
  this.fridaSession
    .typeDelete(id)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
