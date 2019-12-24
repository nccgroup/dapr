import * as express from "express";
/*
   # API Definition
   GET /events/:id

   # Description
   Returns an event for a given id, which is an index into an array of events.

   # Path Parameters
   id: Integer     - The index of an event

   # Response Body
   [Event]
 */
export const getEvent = (req: express.Request, res: express.Response) => {
  const index = parseInt(req.params.index, 10);
  if (index < 0 || index >= this.syscallEvents.length) {
    res.status(500).send("Invalid index");
  } else {
    res.send(this.syscallEvents[index]);
  }
};
