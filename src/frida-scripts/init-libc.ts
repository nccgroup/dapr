import { map, filter } from "lodash";
import { hookIoctl } from "./hooks/hook-ioctl";
import { hookClose } from "./hooks/hook-close";
import { hookOpen } from "./hooks/hook-open";
import { hookOpenAt } from "./hooks/hook-openat";
import { hookSocket } from "./hooks/hook-socket";
import { hookOpenGeneric } from "./hooks/hook-open-generic";

export const getLibcModuleNames = (): string[] =>
  filter(
    map(Process.enumerateModules(), m => {
      if (m.name.match(/^libc[\.\-]/).length > 0) {
        return m.name;
      }
      return "";
    }),
    m => m !== ""
  );

export const installHooks = (module: string, files: {}) => {
  hookIoctl(module, files);
  hookClose(module, files);
  hookOpen(module, files);
  hookOpenAt(module, files);
  hookSocket(module, files);
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
