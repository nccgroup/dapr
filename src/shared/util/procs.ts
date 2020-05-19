import { spawnSync, SpawnSyncReturns } from "child_process";
import { memoize } from "lodash";

// isRoot returns if the current running user is the root user.
export const isRoot = (): boolean => {
  // We only check if we are root in the ADB setting
  const commandResult = shell(["id"], true);
  if (commandResult.status === 0) {
    if (
      commandResult.output[1].toString().search("uid=0") < 0 &&
      commandResult.output[1].toString().search("(root)") < 0
    ) {
      return true;
    }
  }
  return false;
};

// adbShell is a shell function that can be used with ADB.
export const adbShell = (
  command: string[],
  isRoot: boolean
): SpawnSyncReturns<string> =>
  spawnSync("adb", ["shell", ...(isRoot ? ["su", "-c"] : []), ...command]);

// shell is a generic shell command that can be used for both ADB and linux.
export const shell = (
  command: string[],
  adb: boolean
): SpawnSyncReturns<string> => {
  if (adb) {
    return adbShell(command, memoIsRoot());
  }
  const args = command.length === 1 ? [] : command.slice(1, command.length);
  return spawnSync(command[0], args);
};

// resolveFileDescriptor uses the readlink command to resolve the symbolic
// links of the proc filesystem to get the driver name that proc is sending
// syscalls to. Note that this is probably not super accurate.
export const resolveFileDescriptor = (
  pid: number,
  fd: number,
  adb: boolean
): string | null => {
  const commandResult = shell(["readlink", `/proc/${pid}/fd/${fd}`], adb);
  if (commandResult.status === 0 && commandResult.output.length >= 2) {
    return commandResult.output[1].toString().trim();
  }
  return null;
};

// During the course of running this tool, it's likely these
// values will not change. The file descriptor resolution might
// so keep an eye on that one.
export const memoIsRoot = memoize(isRoot);
export const memoResolveFileDescriptor = memoize(resolveFileDescriptor);
