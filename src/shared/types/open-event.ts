import { SyscallType } from "./syscalls";
import { Mode } from "./mode";

export interface OpenEvent {
  syscall: SyscallType;
  driverName: string;
  mode: Mode;
  retval: number;
  start: number;
  end: number;
}
