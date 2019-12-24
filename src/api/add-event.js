"use strict";
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
/*
   # API Definition
   POST /events

   # Description
   Synchronously inject a series of events into the target process.

   # Request Body Parameters
   [InjectInput, ...]

   # Response Body
   [InjectOutput, ...]

   # Types
   InjectInput:
   syscall: String           - "ioctl" for now
   fd: Integer               - first arg of ioctl syscall
   request: String | Integer - second arg of ioctl syscall; hex-encoded string or raw integer value
   data: Integer[] | null    - third arg of ioctl syscall; byte-array of data or null

   InjectOutput:
   data: Integer[] | null    - third arg of ioctl syscall; may be populated with output data from the target driver.
   retval: Integert          - return value of the ioctl syscall
 */
exports.addEvent = function (req, res, _) {
    var syscalls = req.body;
    if (!syscalls || syscalls.length === 0 || syscalls.constructor !== Array) {
        res.status(500).send("Bad input");
    }
    else {
        _this.fridaSession
            .inject(syscalls)
            .then(function (results) {
            res.send(results);
        })
            .catch(function (e) {
            res.status(500).send(e.toString());
        });
    }
};
