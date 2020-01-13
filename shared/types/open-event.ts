///<reference path="mode.ts"/>
///<reference path="syscalls.ts"/>
namespace SharedTypes {
  export interface OpenEvent {
    syscall: SyscallType;
    driverName: string;
    mode: Mode;
    retval: number;
    start: number;
    end: number;
  }
}
