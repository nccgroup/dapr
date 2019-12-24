"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /types/:id

   # Description
   Update a type definition

   # Path Parameters
   id: Integer

   # Request Body Parameters
   TypeDef
 */
exports.updateType = function (req, resp) {
    var id = parseInt(req.params.id, 10);
    var type = req.body;
    _this.fridaSession
        .typeUpdate(id, type)
        .then(function () { return resp.send(); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
