export enum SyscallType {
  OPEN,
  CLOSE,
  SOCKET,
  IOCTL
}

export interface Syscall {
  type: string;
  syscall: SyscallType;
  fd: number;
  request: number;
  data: ArrayBuffer;
}
