import * as express from "express";
/*
   # API Definition
   GET /events/range/:begin

   # Description
   Returns a range of events starting at a given index.

   # Path Parameters
   begin: Integer     - The beginning event index

   # Response Body
   [Event, ...]
 */
export const getEventsRangeStart = (
  req: express.Request,
  res: express.Response
) => {
  const begin = parseInt(req.params.begin, 10);
  if (begin < 0 || begin >= this.syscallEvents.length) {
    res.status(500).send("Invalid range");
  } else {
    res.send(this.syscallEvents.slice(begin, this.syscallEvents.length));
  }
};
