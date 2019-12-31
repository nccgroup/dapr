import { first } from "lodash";
import { IoctlEvent } from "../../../shared/types/ioctl-event";
import { Mode } from "../../../shared/types/mode";
import { SyscallType } from "../../../shared/types/syscalls";

export const hookIoctl = (libcModuleName: string, files: {}) => {
  Interceptor.attach(Module.findExportByName(libcModuleName, "ioctl"), {
    onEnter: args => {
      this.start = new Date().getTime();
      this.fd = parseInt(first(args).toString());
      this.driverName = this.fd in files ? files[this.fd] : null;
      this.request = parseInt(args[1].toString());
      this.opcode = this.request & 0xff;
      this.chr = (this.request >> 8) & 0xff;
      this.size = (this.request >> 16) & ((1 << 0xe) - 1);
      this.modebits = (this.request >> 30) & ((1 << 0x2) - 1);
      this.mode = "";
      switch (this.modebits) {
        case 0:
          this.mode = Mode.UNSURE;
          break;
        case 1:
          this.mode = Mode.WRITE;
          break;
        case 2:
          this.mode = Mode.READ;
          break;
        case 3:
          this.mode = Mode.READ_WRITE;
          break;
      }

      this.data = null;
      if (this.size > 0) {
        try {
          this.data = args[2].readByteArray(this.size);
        } catch (e) {
          this.data = parseInt(args[2].toString());
        }
      }
      return 0;
    },
    onLeave: retval => {
      if (!this.driverName) {
        this.driverName = this.fd in files ? files[this.fd] : null;
      }
      const ioctlEvent: IoctlEvent = {
        syscall: SyscallType.IOCTL,
        fd: this.fd,
        driverName: this.driverName,
        mode: this.mode,
        size: this.size,
        opcode: this.opcode,
        request: this.request.toString(16),
        retval: parseInt(retval.toString()),
        start: this.start,
        end: new Date().getTime()
      };

      if (this.data instanceof Object) {
        send(ioctlEvent, this.data);
      } else {
        send(ioctlEvent, null);
      }
      return retval;
    }
  });
};
