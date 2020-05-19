import { action } from "typesafe-actions";
import { Syscall } from "../../../shared/types/syscalls";

export const SELECT_PROCESS = "SELECT_PROCESS";
export const ADD_EVENT = "ADD_EVENT";
export const ADD_EVENTS = "ADD_EVENTS";
export const SELECT_EVENT = "SELECT_EVENT";
export const CLEAR_EVENTS = "CLEAR_EVENTS";

export const clearEvents = () => action(CLEAR_EVENTS);
export const addEvent = (e: Syscall) => action(ADD_EVENT, e);
export const addEvents = (e: Syscall[]) => action(ADD_EVENTS, e);
export const selectProcess = (proc: { pid: number; processName: string }) =>
  action(SELECT_PROCESS, proc);
export const selectEvent = (i: number) => action(SELECT_EVENT, i);
