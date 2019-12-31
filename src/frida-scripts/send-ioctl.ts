const ioctl = (libcModuleName: string) =>
  new NativeFunction(Module.findExportByName(libcModuleName, "ioctl"), "int", [
    "int",
    "ulong",
    "...",
    "pointer"
  ]);

export interface IoctlResponse {
  retval: NativeReturnValue;
  data: number[];
}
export const sendIoctl = (
  libcModuleName: string,
  fd: number,
  request: number,
  data: ArrayBuffer
): IoctlResponse => {
  let _data: NativePointer;

  if (!!data) {
    _data = Memory.alloc(data.byteLength);
    _data.writeByteArray(data);
  } else {
    _data = ptr("0x0");
  }

  const ret = ioctl(libcModuleName)(fd, request, _data);

  let outData: number[] = [];
  if (!!data) {
    outData = Array.prototype.slice.call(
      new Uint8Array(_data.readByteArray(data.byteLength))
    );
  }

  return { retval: ret, data: outData };
};
