import { Request, Response } from "express";
import { events } from "../store/db";

/*
   # API Definition
   GET /events
   # Description
   An HTTP/RESTful version of the websocket streaming API.
   # Response Body
   [Event, ...]
 */
export const getEvents = (_: Request, res: Response) => {
  res.send(events.find());
};
