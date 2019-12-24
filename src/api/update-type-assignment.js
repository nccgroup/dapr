"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /typesAssignments/:id

   # Description
   Update a TypeAssignment

   # Path Parameters
   id: Integer        - ID of type assignment

   # Request Body Parameters
   typeId: Integer
   matcher: EventMatcher
 */
exports.updateTypeAssignment = function (req, resp) {
    var id = parseInt(req.params.id, 10);
    var typeId = req.body.typeId;
    var matcher = req.body.matcher;
    _this.fridaSession
        .typeAssignUpdate(id, typeId, matcher)
        .then(function () { return resp.send(); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
