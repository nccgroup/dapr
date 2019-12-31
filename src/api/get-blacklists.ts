import { Request, Response } from "express";

/*
   # API Definition
   GET /blacklist

   # Description
   Returns all blacklisted EventMatchers.

   Note: The purpose of the blacklist is to let the user filter out events that they do not want to see. This improves
   performance because irrelevant events do not need to be shuffled across process/device boundaries and rendered
   in the UI.

   Users submit an "EventMatcher" which are used to tag events where a field matches a certain value. For
   example, to blacklist all events for the driver /dev/binder, you would need an event matcher where the field
   is "driverName" is "/dev/binder".

   # Response Body
   [EventMatcher, ...]

   # Types
   EventMatcher:
   field: String     - Name of the Event field to match on
   value: String     - Value of the Event field to match on
   regex: boolean    - Value is a regular expression
 */
export const getBlacklists = (_: Request, resp: Response) => {
  this.fridaSession
    .blacklistGetAll()
    .then(result => resp.send(result))
    .catch(e => resp.status(500).send(e.toString()));
};
