"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var frida_session_1 = require("./../frida_session");
exports.statusPending = function (_, res, next) {
    if (
    // TODO: fix this
    !!_this.fridaSession &&
        _this.fridaSession.status === frida_session_1.SessionStatus.PENDING) {
        res.status(500).send("Operation pending");
        res.end();
    }
    else {
        next();
    }
};
