import { Mode } from "../../shared/types/mode";
import { SyscallType } from "../../shared/types/syscalls";
import { hook } from "./hook";
export const hookOpenAt = (libcModule: Module) => {
  hook(libcModule, "openat", {
    onEnter: function(
      this: InvocationContext,
      args: InvocationArguments
    ): void {
      this.start = new Date().getTime();
      this.driverName = "openat:" + args[0].readCString();
      this.mode = Mode.READ; // HACK
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
