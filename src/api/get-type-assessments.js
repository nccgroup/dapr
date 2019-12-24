"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   GET /typesAssignments

   # Description
   Get all type assignments.

   Note: The purpose of type assignments is to associate a TypeDef with an EventMatcher. For each Event that matches
   the criteria of the EventMatcher, Dapr applies special attributes of the TypeDef, which may alter how Dapr
   handles the event.

   # Response Body
   [TypeAssignment, ...]

   # Types
   TypeAssignment:
   matcher: Matcher
   typeId: Integer
 */
exports.getTypeAssessments = function (_, resp) {
    _this.fridaSession
        .typeAssignGetAll()
        .then(function (result) { return resp.send(result); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
