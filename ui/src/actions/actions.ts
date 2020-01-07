import { action } from "typesafe-actions";
import { Syscall } from "../../../shared/types/syscalls";
import { StructDef } from "../types/struct-def";

export const SELECT_PROCESS = "SELECT_PROCESS";
// DRIVER SELECTION DASHBOARD ACTIONS
export const ADD_EVENT = "ADD_EVENT";
export const ADD_EVENTS = "ADD_EVENTS";
export const SELECT_DRIVER = "SELECT_DRIVER";
export const SELECT_DUP_EVENT = "SELECT_DUP_EVENT";
export const SELECT_EVENT = "SELECT_EVENT";
export const BACK = "BACK";
export const addEvent = (e: Syscall) => action(ADD_EVENT, e);
export const addEvents = (e: Syscall[]) => action(ADD_EVENTS, e);
export const selectDriver = (d: string) => action(SELECT_DRIVER, d);
export const selectDupEvent = (i: string) => action(SELECT_DUP_EVENT, i);
export const back = () => action(BACK);
// EVENT DASHBOARD ACTIONS

export const SELECT_HISTORY_EVENT = "SELECT_HISTORY_EVENT";
export const selectProcess = (pid: string) => action(SELECT_PROCESS, pid);
export const selectEvent = (i: number) => action(SELECT_EVENT, i);
export const selectHistoryEvent = (i: number) =>
  action(SELECT_HISTORY_EVENT, i);

export const SAVE_TYPE = "SAVE_TYPE";
export const DISSECTOR_SELECT_TYPE = "DISSECTOR_SELECT_TYPE";
export const EDITOR_SELECT_TYPE = "EDITOR_SELECT_TYPE";

export const saveType = (t: StructDef) => action(SAVE_TYPE, t);
export const dissectorSelectType = (s: string) =>
  action(DISSECTOR_SELECT_TYPE, s);
export const editorSelectType = (s: string) => action(EDITOR_SELECT_TYPE, s);
