"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
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
exports.getEventsRangeStart = function (req, res) {
    var begin = parseInt(req.params.begin, 10);
    if (begin < 0 || begin >= _this.syscallEvents.length) {
        res.status(500).send("Invalid range");
    }
    else {
        res.send(_this.syscallEvents.slice(begin, _this.syscallEvents.length));
    }
};
