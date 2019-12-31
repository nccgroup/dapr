import { OpenEvent } from "../../../shared/types/open-event";
import { Mode } from "../../../shared/types/mode";
import { SyscallType } from "../../../shared/types/syscalls";
export const hookOpenGeneric = (
  libcModuleName: string,
  hookFunctionName: string
) => {
  Interceptor.attach(
    Module.findExportByName(libcModuleName, hookFunctionName),
    {
      onLeave: retval => {
        const ret = parseInt(retval.toString());
        if (ret >= 0) {
          const event: OpenEvent = {
            syscall: SyscallType.OPEN,
            driverName: "anon_inode:[" + hookFunctionName + "]",
            mode: Mode.READ,
            retval: ret,
            start: 0,
            end: new Date().getTime()
          };
          send(event);
        }
        return retval;
      }
    }
  );
};
