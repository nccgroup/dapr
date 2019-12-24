import * as express from "express";

/*
   # API Definition
   POST /blacklist/:id/delete

   # Description
   Delete an EventMatcher in the blacklist

   # Request Body Parameters
   id: Integer
 */
export const deleteEventMatcherFromBlacklist = (
  req: express.Request,
  resp: express.Response
) => {
  const id = parseInt(req.params.id, 10);
  this.fridaSession
    .blacklistDelete(id)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
