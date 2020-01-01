import { Mode } from "./mode";
import { SyscallType } from "../types/syscalls";
export interface IoctlEvent {
  syscall: SyscallType;
  fd: number;
  driverName: string;
  mode: Mode;
  size: number;
  opcode: number;
  request: string;
  retval: number;
  start: number;
  end: number;
}
