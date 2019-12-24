import * as express from "express";
import { Syscall } from "../types/syscalls";
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
export const addEvent = (
  req: express.Request,
  res: express.Response,
  _: express.NextFunction
) => {
  const syscalls: Syscall[] = req.body;
  if (!syscalls || syscalls.length === 0 || syscalls.constructor !== Array) {
    res.status(500).send("Bad input");
  } else {
    //TODO: fix this
    this.fridaSession
      .inject(syscalls)
      .then(results => {
        res.send(results);
      })
      .catch(e => {
        res.status(500).send(e.toString());
      });
  }
};
