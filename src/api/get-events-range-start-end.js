"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   GET /events

   # Description
   An HTTP/RESTful version of the websocket streaming API.

   # Response Body
   [Event, ...]
 */
exports.getEvents = function (req, res) {
    res.send(_this.syscallEvents.slice(_this.lastEmittedIndex, _this.syscallEvents.length));
    _this.lastEmittedIndex = _this.syscallEvents.length;
};
