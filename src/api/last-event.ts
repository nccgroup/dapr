/*
   # API Definition
   GET /last-event

   # Description
   Returns the index/id of the event last emitted over websocket or via `GET /events`.

   # Response Body
   index: Integer
 */
export const lastEvent = (req, res) => {
  res.send({ index: this.lastEmittedIndex });
};
