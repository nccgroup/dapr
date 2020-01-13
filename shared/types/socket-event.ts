///<reference path="syscalls.ts"/>
namespace SharedTypes {
  export interface SocketEvent {
    syscall: SyscallType;
    domain: number;
    type: number;
    protocol: number;
    retval: number;
    start: number;
    end: number;
  }
}
