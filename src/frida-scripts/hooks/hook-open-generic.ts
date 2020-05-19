import { hook } from "./hook";
import { SyscallType } from "../../shared/types/syscalls";
import { Mode } from "../../shared/types/mode";
export const hookOpenGeneric = (
  libcModule: Module,
  hookFunctionName: string
) => {
  hook(libcModule, hookFunctionName, {
    onLeave: function(
      this: InvocationContext,
      retval: InvocationReturnValue
    ): void {
      send({
        syscall: SyscallType.OPEN,
        driverName: "anon_inode:[" + hookFunctionName + "]",
        mode: Mode.READ,
        retval: retval.toInt32(),
        start: 0,
        end: new Date().getTime()
      });
    }
  });
};
