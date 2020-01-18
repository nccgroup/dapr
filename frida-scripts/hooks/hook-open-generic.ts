import { hook } from "./hook";

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
        syscall: SharedTypes.SyscallType.OPEN,
        driverName: "anon_inode:[" + hookFunctionName + "]",
        mode: SharedTypes.Mode.READ,
        retval: retval.toInt32(),
        start: 0,
        end: new Date().getTime()
      });
    }
  });
};
