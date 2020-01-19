"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   GET /last-event

   # Description
   Returns the index/id of the event last emitted over websocket or via `GET /events`.

   # Response Body
   index: Integer
 */
exports.lastEvent = function (req, res) {
    res.send({ index: _this.lastEmittedIndex });
};
