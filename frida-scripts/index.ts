import { first, map, filter } from "lodash";
import { getLibcModules, installHooks } from "./init-libc";
import { sendIoctl, IoctlResponse } from "./send-ioctl";

rpc.exports = {
  hook: (): void => {
    const libcModules = getLibcModules();
    if (libcModules.length === 0) {
      console.log("No libc in this module");
      return;
    }

    const module = first(libcModules);
    installHooks(module);
  },
  send: (syscalls: SharedTypes.Syscall[]): IoctlResponse[] =>
    filter(
      map(syscalls, (syscall): IoctlResponse | null => {
        if (syscall.syscall !== SharedTypes.SyscallType.IOCTL) {
          console.debug("Must be of type syscall.IOCTL");
          return null;
        }

        const libcModuleNames = getLibcModules();
        if (libcModuleNames.length === 0) {
          console.debug("No libc in this module");
          return null;
        }

        const module = first(libcModuleNames);
        return sendIoctl(
          module.name,
          syscall.fd,
          syscall.request,
          syscall.data
        );
      }),
      r => r !== null
    )
};
