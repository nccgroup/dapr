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

/*
   # API Definition
   GET /events/range/:begin/:end

   # Description
   Returns a range of events beginning and ending at the given indices.

   # Path Parameters
   begin: Integer     - The beginning event index
   end: Integer       - The end event index

   # Response Body
   [Event, ...]
 */
export const getEventsRangeStartEnd = (
  req: express.Request,
  res: express.Response
) => {
  const begin = parseInt(req.params.begin, 10);
  const end = parseInt(req.params.end, 10);
  if (
    begin < 0 ||
    begin >= this.syscallEvents.length ||
    end < 0 ||
    end >= this.syscallEvents.length ||
    end < begin
  ) {
    res.status(500).send("Invalid range");
  } else {
    res.send(this.syscallEvents.slice(begin, end));
  }
};
