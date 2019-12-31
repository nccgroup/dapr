import { Request, Response } from "express";
import * as _ from "lodash";
import { events } from "../store/db";
/*
   # API Definition
   GET /events

   # Description
   An HTTP/RESTful version of the websocket streaming API.

   # Response Body
   [Event, ...]
 */
export const getEventsRangeStartEnd = (req: Request, res: Response) => {
  const { begin, end } = req.params;
  const range = events.find({
    $and: [{ id: { $gte: begin } }, { id: { $lt: end } }]
  });
  res.send(range);
};
