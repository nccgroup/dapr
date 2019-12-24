"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /session/detach

   # Description
   Detach from a Frida session.

   Note: The result of this operation can be checked by polling /session/status.
 */
app.post("/session/detach", function (req, res, next) {
    console.log("detaching from " + _this.fridaSession.session.pid);
    try {
        _this.detach();
        res.send();
    }
    catch (e) {
        res.status(500).send(e.toString());
    }
});
