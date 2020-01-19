import { first, map } from "lodash";
import { getLibcModules, installHooks } from "./init-libc";
import { sendIoctl, IoctlResponse } from "./send-ioctl";
import { Syscall, SyscallType } from "../shared/types/syscalls";
rpc.exports = {
  hook: (): void => {
    const libcModules = getLibcModules();
    if (libcModules.length === 0) {
      console.log("No libc in this module");
      return;
    }
    console.log("hooking. libcmodules: ", libcModules.length);
    const module = first(libcModules);
    if (!module) {
      console.log("No libc in this module");
      return;
    }
    console.log("module", module.name);
    installHooks(module);
  },
  send: (syscalls: Syscall[]): (IoctlResponse | null)[] =>
    map(syscalls, (syscall): IoctlResponse | null => {
      if (syscall.syscall !== SyscallType.IOCTL) {
        console.debug("Must be of type syscall.IOCTL");
        return null;
      }

      const libcModuleNames = getLibcModules();
      if (libcModuleNames.length === 0) {
        console.debug("No libc in this module");
        return null;
      }

      const module = first(libcModuleNames);
      if (!module) {
        console.log("No libc in this module");
        return null;
      }
      return sendIoctl(module.name, syscall.fd, syscall.request, syscall.data);
    })
};
