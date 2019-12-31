import { Mode } from "./mode";
import { SyscallType } from "../types/syscalls";

export interface OpenEvent {
  syscall: SyscallType;
  driverName: string;
  mode: Mode;
  retval: number;
  start: number;
  end: number;
}
