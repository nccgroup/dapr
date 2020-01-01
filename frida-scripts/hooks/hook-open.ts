import { OpenEvent } from "../../shared/types/open-event";
import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookOpen = (libcModule: Module) => {
  hook(libcModule, "open", {
    onEnter: args => {
      this.start = new Date().getTime();
      this.driverName = args[0].readCString();
      this.mode = args[1];
      return 0;
    },
    onLeave: retval => {
      const ret = parseInt(retval.toString());

      const event: OpenEvent = {
        syscall: SyscallType.OPEN,
        driverName: this.driverName,
        mode: this.mode,
        retval: ret,
        start: this.start,
        end: new Date().getTime()
      };
      send(event);
      return retval;
    }
  });
};
