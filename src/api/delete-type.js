"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /types/:id/delete

   # Description
   Delete a type definition

   # Path Parameters
   id: Integer
 */
exports.deleteType = function (req, resp) {
    var id = parseInt(req.params.id, 10);
    _this.fridaSession
        .typeDelete(id)
        .then(function () { return resp.send(); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
