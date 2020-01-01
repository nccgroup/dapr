import { OpenEvent } from "../../shared/types/open-event";
import { Mode } from "../../shared/types/mode";
import { first } from "lodash";
import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookOpenAt = (libcModule: Module) => {
  hook(libcModule, "openat", {
    onEnter: args => {
      this.start = new Date().getTime();
      this.driverName = "openat:" + first(args).readCString();
      this.mode = Mode.READ; // HACK
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
