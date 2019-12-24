"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var _ = require("lodash");
/*
   # API Definition
   POST /session/attach

   # Description
   Asynchronously attaches Frida to a `target` process, which can be either a process ID or process name. On success,
   Dapr begins hooking system calls and streams events to websocket clients.

   Note: The result of this operation can be checked by polling /session/status.

   # Request Body Parameters
   target: Integer | String      - process ID or process name
 */
exports.sessionAttach = function (req, res) {
    var _a = req.body, target = _a.target, adb = _a.adb;
    if (_.isNumber(target)) {
        target = _.parseInt(target);
    }
    try {
        _this.attach(target, adb);
        res.send();
    }
    catch (e) {
        res.status(500).send(e.toString());
    }
};
