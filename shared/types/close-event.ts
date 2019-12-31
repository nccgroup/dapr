import { SyscallType } from "../types/syscalls";
export interface CloseEvent {
  syscall: SyscallType;
  fd: number;
  driverName: string;
  retval: number;
  start: number;
  end: number;
}
