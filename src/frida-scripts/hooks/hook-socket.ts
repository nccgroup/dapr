import { SocketEvent } from "../../../shared/types/socket-event";
import { SyscallType } from "../../../shared/types/syscalls";
export const hookSocket = (libcModuleName: string, files: {}) => {
  Interceptor.attach(Module.findExportByName(libcModuleName, "socket"), {
    onEnter: args => {
      this.start = new Date().getTime();
      this.domain = parseInt(args[0].toString());
      this.type = parseInt(args[1].toString());
      this.protocol = parseInt(args[2].toString());
      return 0;
    },
    onLeave: retval => {
      const ret = parseInt(retval.toString());
      if (ret >= 0) {
        files[ret] =
          "socket:" + this.domain + ":" + this.type + ":" + this.protocol;
      }
      const event: SocketEvent = {
        syscall: SyscallType.SOCKET,
        domain: this.domain,
        type: this.type,
        protocol: this.protocol,
        retval: ret,
        start: this.start,
        end: new Date().getTime()
      };
      send(event);
      return retval;
    }
  });
};
