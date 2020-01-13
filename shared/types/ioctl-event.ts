///<reference path="mode.ts"/>
///<reference path="syscalls.ts"/>
namespace SharedTypes {
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
}
