import { filter } from "lodash";
import { hookIoctl } from "./hooks/hook-ioctl";
import { hookClose } from "./hooks/hook-close";
import { hookOpen } from "./hooks/hook-open";
import { hookOpenAt } from "./hooks/hook-openat";
import { hookSocket } from "./hooks/hook-socket";
import { hookOpenGeneric } from "./hooks/hook-open-generic";

export const getLibcModules = (): Module[] =>
  filter(Process.enumerateModules(), (m: Module): boolean => {
    const matches = m.name.match(/^libc[\.\-]/);
    if (matches === null) {
      return false;
    }
    return matches.length > 0;
  });

export const installHooks = (module: Module) => {
  hookIoctl(module);
  hookClose(module);
  hookOpen(module);
  hookOpenAt(module);
  hookSocket(module);
  hookOpenGeneric(module, "dup");
  hookOpenGeneric(module, "dup2");
  hookOpenGeneric(module, "dup3");
  hookOpenGeneric(module, "epoll_create");
  hookOpenGeneric(module, "epoll_create1");
  hookOpenGeneric(module, "eventfd");
  hookOpenGeneric(module, "inotify_init");
  hookOpenGeneric(module, "signalfd");
  hookOpenGeneric(module, "timerfd_create");
};
