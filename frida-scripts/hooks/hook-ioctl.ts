import { hook } from "./hook";

export const hookIoctl = (libcModule: Module) => {
  hook(libcModule, "ioctl", {
    onEnter: function(
      this: InvocationContext,
      args: InvocationArguments
    ): void {
      this.start = new Date().getTime();
      this.fd = args[0].toInt32();
      this.request = args[1].toInt32();
      this.opcode = this.request & 0xff;
      this.size = (this.request >> 16) & ((1 << 0xe) - 1);
      this.modebits = (this.request >> 30) & ((1 << 0x2) - 1);
      switch (this.modebits) {
        case 0:
          this.mode = SharedTypes.Mode.UNSURE;
          break;
        case 1:
          this.mode = SharedTypes.Mode.WRITE;
          break;
        case 2:
          this.mode = SharedTypes.Mode.READ;
          break;
        case 3:
          this.mode = SharedTypes.Mode.READ_WRITE;
          break;
      }

      this.data = null;
      if (this.size > 0) {
        this.data = args[2].readByteArray(this.size);
      }
    },
    onLeave: function(
      this: InvocationContext,
      retval: InvocationReturnValue
    ): void {
      send(
        {
          syscall: SharedTypes.SyscallType.IOCTL,
          fd: this.fd,
          driverName: this.driverName,
          mode: this.mode,
          size: this.size,
          opcode: this.opcode,
          request: this.request.toString(16),
          retval: retval.toInt32(),
          start: this.start,
          end: new Date().getTime()
        },
        this.data
      );
    }
  });
};
