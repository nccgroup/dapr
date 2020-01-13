///<reference path="syscalls.ts"/>
namespace SharedTypes {
  export interface CloseEvent {
    syscall: SyscallType;
    fd: number;
    retval: number;
    start: number;
    end: number;
  }
}
