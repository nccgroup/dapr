import { SyscallType } from "../types/syscalls";
export interface CloseEvent {
  syscall: SyscallType;
  fd: number;
  retval: number;
  start: number;
  end: number;
}
