export enum SyscallType {
  OPEN,
  CLOSE,
  SOCKET,
  IOCTL
}

export interface Syscall {
  syscall: SyscallType;
  fd: number;
  request: number;
  data: ArrayBuffer;
}
