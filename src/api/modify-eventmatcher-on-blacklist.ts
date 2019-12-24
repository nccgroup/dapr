import * as express from "express";
import { EventMatcher } from "../types/event-matcher";

/*
   # API Definition
   POST /blacklist/:id

   # Description
   Update an EventMatcher in the blacklist

   # Request Body Parameters
   id: Integer
   matcher: EventMatcher
 */
export const modifyEventMatcherToBlacklist = (
  req: express.Request,
  resp: express.Response
) => {
  const id = parseInt(req.params.id, 10);
  const matcher: EventMatcher = req.body;
  this.fridaSession
    .blacklistUpdate(id, matcher)
    .then(() => resp.send())
    .catch(e => resp.status(500).send(e.toString()));
};
