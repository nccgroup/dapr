import { Request, Response } from "express";
import { Syscall } from "../../shared/types/syscalls";
import { getFridaSession } from "../frida-session";

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
export const addEvent = async (req: Request, res: Response) => {
  const syscalls: Syscall[] = req.body;
  const session = getFridaSession();
  if (session === null) {
    res.status(500).end();
    return;
  }

  try {
    const results = await session.send(syscalls);
    res.send(results);
  } catch (e) {
    res.status(500).send(e.toString());
  }
};
