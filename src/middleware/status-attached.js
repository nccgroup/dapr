"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var frida_session_1 = require("./../frida_session");
exports.statusAttached = function (_, res, next) {
    //TODO: fix this
    if (!_this.fridaSession ||
        _this.fridaSession.status !== frida_session_1.SessionStatus.ATTACHED) {
        res.status(500).send("Must be attached");
        res.end();
    }
    else {
        next();
    }
};
