import { first, map, filter } from "lodash";
import { getLibcModuleNames, installHooks } from "./init-libc";
import { sendIoctl, IoctlResponse } from "./send-ioctl";
import { Syscall, SyscallType } from "../../shared/types/syscalls";

rpc.exports = {
  init: (fdMap: { [key: string]: string }): void => {
    const libcModuleNames = getLibcModuleNames();
    if (libcModuleNames.length === 0) {
      console.log("No libc in this module");
      return;
    }

    const module = first(libcModuleNames);
    this.files = fdMap;
    installHooks(module, fdMap);
  },

  getFDs: (): { [key: string]: string } => {
    return this.files;
  },
  setFD: (fd: string, path: string): void => {
    this.files[fd] = path;
  },
  getFD: (fd: string): string | null => {
    return fd in this.files ? this.files[fd] : null;
  },

  send: (syscalls: Syscall[]): IoctlResponse[] =>
    filter(
      map(syscalls, (syscall): IoctlResponse | null => {
        if (syscall.syscall !== SyscallType.IOCTL) {
          console.debug("Must be of type syscall.IOCTL");
          return null;
        }

        const libcModuleNames = getLibcModuleNames();
        if (libcModuleNames.length === 0) {
          console.debug("No libc in this module");
          return null;
        }

        const module = first(libcModuleNames);
        return sendIoctl(module, syscall.fd, syscall.request, syscall.data);
      }),
      r => r !== null
    )
};
