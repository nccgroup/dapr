import { first, filter } from "lodash";

export const hook = (
  libcModule: Module,
  exportName: string,
  hookBehavior: ScriptInvocationListenerCallbacks
) => {
  const pointer = first(
    filter(libcModule.enumerateExports(), p => p.name === exportName)
  );
  if (!pointer) {
    console.error(`No export named "${exportName}"`);
    return;
  }
  Interceptor.attach(pointer.address, hookBehavior);
};
