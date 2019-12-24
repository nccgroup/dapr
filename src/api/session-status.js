"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var frida_session_1 = require("./../frida_session");
/*
   # API Definition
   GET /session/status

   # Description
   Returns the current state of the Frida session. Poll this API after doing an `attach` or `detach`. When the status
   is "attached", the process ID is also returned.

   # Request Body Parameters
   N/A

   # Response Body
   status: string
   pid: Integer or Undefined
*/
exports.sessionStatus = function (req, res) {
    var out = {};
    if (!_this.fridaSession) {
        out.status = "detached";
    }
    else {
        switch (_this.fridaSession.status) {
            case frida_session_1.SessionStatus.ATTACHED:
                out.status = "attached";
                out.pid = _this.fridaSession.session.pid;
                break;
            case frida_session_1.SessionStatus.FAILED:
                out.status = "failed";
                out.reason = _this.fridaSession.reason.message.toString();
                break;
            case frida_session_1.SessionStatus.PENDING:
                out.status = "pending";
                break;
            case frida_session_1.SessionStatus.DETACHED:
                out.status = "detached";
                break;
            default:
                throw new Error("unknown status");
        }
    }
    res.send(out);
};
