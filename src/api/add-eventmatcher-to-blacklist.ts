import * as express from "express";
import { EventMatcher } from "../types/event-matcher";

/*
   # API Definition
   POST /blacklist

   # Description
   Put an EventMatcher in the blacklist

   # Request Body Parameters
   EventMatcher

   # Response Body
   id: Integer   - id/index of the blacklist item
 */
export const addEventMatcherToBlacklist = (
  req: express.Request,
  resp: express.Response
) => {
  const matcher: EventMatcher = req.body;
  this.fridaSession
    .blacklistPut(matcher)
    .then(res => resp.send({ id: res }))
    .catch(e => resp.status(500).send(e.toString()));
};
