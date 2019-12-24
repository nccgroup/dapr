import * as express from "express";
/*
   # API Definition
   GET /events

   # Description
   An HTTP/RESTful version of the websocket streaming API.

   # Response Body
   [Event, ...]
 */
export const getEventsRangeStartEnd = (
  _: express.Request,
  res: express.Response
) => {
  res.send(
    this.syscallEvents.slice(this.lastEmittedIndex, this.syscallEvents.length)
  );
  this.lastEmittedIndex = this.syscallEvents.length;
};
