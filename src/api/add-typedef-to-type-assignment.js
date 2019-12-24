"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /typesAssignments

   # Description
   Assign a TypeDef to an EventMatcher.

   # Request Body Parameters
   typeId: Integer
   matcher: EventMatcher

   # Response Body
   id: Integer        - ID of type assignment
 */
exports.typeAssignment = function (req, resp) {
    var typeId = req.body.typeId;
    var matcher = req.body.matcher;
    _this.fridaSession
        .typeAssignPut(typeId, matcher)
        .then(function (res) { return resp.send({ id: res }); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
