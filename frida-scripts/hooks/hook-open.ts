import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookOpen = (libcModule: Module) => {
  hook(libcModule, "open", {
    onEnter: function(
      this: InvocationContext,
      args: InvocationArguments
    ): void {
      this.start = new Date().getTime();
      this.driverName = args[0].readCString();
      this.mode = args[1];
    },
    onLeave: function(
      this: InvocationContext,
      retval: InvocationReturnValue
    ): void {
      send({
        syscall: SyscallType.OPEN,
        driverName: this.driverName,
        mode: this.mode,
        retval: retval.toInt32(),
        start: this.start,
        end: new Date().getTime()
      });
    }
  });
};
