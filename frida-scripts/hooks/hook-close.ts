import { CloseEvent } from "../../shared/types/close-event";
import { first } from "lodash";
import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookClose = (libcModule: Module) => {
  hook(libcModule, "close", {
    onEnter: args => {
      this.start = new Date().getTime();
      this.fd = parseInt(first(args).toString());
      return 0;
    },
    onLeave: retval => {
      const ret = parseInt(retval.toString());

      const event: CloseEvent = {
        syscall: SyscallType.CLOSE,
        fd: this.fd,
        retval: ret,
        start: this.start,
        end: new Date().getTime()
      };
      send(event);
      return ret;
    }
  });
};
