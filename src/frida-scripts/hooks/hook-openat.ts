import { OpenEvent } from "../../../shared/types/open-event";
import { Mode } from "../../../shared/types/mode";
import { first } from "lodash";
import { SyscallType } from "../../../shared/types/syscalls";
export const hookOpenAt = (libcModuleName: string, files: {}) => {
  Interceptor.attach(Module.findExportByName(libcModuleName, "openat"), {
    onEnter: args => {
      this.start = new Date().getTime();
      this.driverName = "openat:" + first(args).readCString();
      this.mode = Mode.READ; // HACK
      return 0;
    },
    onLeave: retval => {
      const ret = parseInt(retval.toString());
      if (ret >= 0) {
        files[ret] = this.driverName;
      }
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
