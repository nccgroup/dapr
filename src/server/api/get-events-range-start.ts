import { Request, Response } from "express";
import * as _ from "lodash";
import { events } from "../store/db";
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
export const getEventsRangeStart = (req: Request, res: Response) => {
  const begin = _.parseInt(req.params.begin, 10);
  res.send(events.find({ id: { $gte: begin } }));
};
