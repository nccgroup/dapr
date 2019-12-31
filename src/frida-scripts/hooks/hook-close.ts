import { CloseEvent } from "../../../shared/types/close-event";
import { first } from "lodash";
import { SyscallType } from "../../../shared/types/syscalls";
export const hookClose = (libcModuleName: string, files: {}) => {
  Interceptor.attach(Module.findExportByName(libcModuleName, "close"), {
    onEnter: args => {
      this.start = new Date().getTime();
      this.fd = parseInt(first(args).toString());
      return 0;
    },
    onLeave: retval => {
      const ret = parseInt(retval.toString());
      var driverName = null;
      if (ret >= 0) {
        if (this.fd in files) {
          driverName = files[this.fd];
          delete files[this.fd];
        }
      }
      const event: CloseEvent = {
        syscall: SyscallType.CLOSE,
        fd: this.fd,
        driverName: driverName,
        retval: parseInt(retval.toString()),
        start: this.start,
        end: new Date().getTime()
      };
      send(event);
      return retval;
    }
  });
};
