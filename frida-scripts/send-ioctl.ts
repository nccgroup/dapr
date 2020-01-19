const ioctl = (libcModuleName: string) => {
  const module = Module.findExportByName(libcModuleName, "ioctl");
  if (module === null) {
    console.error('No module named "ioctl"');
    return null;
  }
  return new NativeFunction(module, "int", ["int", "ulong", "...", "pointer"]);
};

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

  if (data.byteLength !== 0) {
    _data = Memory.alloc(data.byteLength);
    _data.writeByteArray(data);
  } else {
    _data = ptr("0x0");
  }

  const ioctlFunc = ioctl(libcModuleName);
  if (ioctlFunc === null) {
    return { retval: 0, data: [] };
  }
  const ret = ioctlFunc(fd, request, _data);

  let outData: number[] = [];
  const arrData = _data.readByteArray(data.byteLength);
  if (arrData !== null) {
    const arr = new Uint8Array(arrData);
    outData = [...arr];
  }

  return { retval: ret, data: outData };
};
