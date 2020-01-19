import { Request, Response } from "express";
/*
   # API Definition
   GET /last-event

   # Description
   Returns the index/id of the event last emitted over websocket or via `GET /events`.

   # Response Body
   index: Integer
 */
//TODO: not really interested in this call. client should control this
/*export const lastEvent = (_: Request, res: Response) => {
  res.send({ index: this.lastEmittedIndex });
};*/
