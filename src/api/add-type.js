"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /types

   # Description
   Define a new type

   # Request Body Parameters
   TypeDef

   # Response Body
   id: Integer
 */
exports.addType = function (req, resp) {
    var type = req.body;
    _this.fridaSession
        .typePut(type)
        .then(function (res) { return resp.send({ id: res }); })
        .catch(function (e) { return resp.status(500).send(e.toString()); });
};
