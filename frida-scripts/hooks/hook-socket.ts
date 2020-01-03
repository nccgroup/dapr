import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookSocket = (libcModule: Module) => {
  hook(libcModule, "socket", {
    onEnter: function(
      this: InvocationContext,
      args: InvocationArguments
    ): void {
      this.start = new Date().getTime();
      this.domain = args[0].toInt32();
      this.type = args[1].toInt32();
      this.protocol = args[2].toInt32();
    },
    onLeave: function(
      this: InvocationContext,
      retval: InvocationReturnValue
    ): void {
      send({
        syscall: SyscallType.SOCKET,
        domain: this.domain,
        type: this.type,
        protocol: this.protocol,
        retval: retval.toInt32(),
        start: this.start,
        end: new Date().getTime()
      });
    }
  });
};
