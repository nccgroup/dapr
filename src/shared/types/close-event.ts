import { SyscallType } from "./syscalls";

export interface CloseEvent {
  syscall: SyscallType;
  fd: number;
  retval: number;
  start: number;
  end: number;
}
