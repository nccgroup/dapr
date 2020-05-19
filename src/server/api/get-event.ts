import { Request, Response } from "express";
import * as _ from "lodash";
import { events } from "../store/db";
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
export const getEvent = (req: Request, res: Response) => {
  const index = _.parseInt(req.params.index, 10);
  res.send(events.findOne({ id: index }));
};
