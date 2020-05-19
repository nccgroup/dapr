import { SyscallType } from "./syscalls";
import { Mode } from "./mode";
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
