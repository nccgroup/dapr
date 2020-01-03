import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookClose = (libcModule: Module) => {
  hook(libcModule, "close", {
    onEnter: function(
      this: InvocationContext,
      args: InvocationArguments
    ): void {
      this.start = new Date().getTime();
      this.fd = args[0].toInt32();
    },
    onLeave: function(
      this: InvocationContext,
      retval: InvocationReturnValue
    ): void {
      send({
        syscall: SyscallType.CLOSE,
        fd: this.fd,
        retval: retval.toInt32(),
        start: this.start,
        end: new Date().getTime()
      });
    }
  });
};
