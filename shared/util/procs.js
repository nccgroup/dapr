"use strict";
var __spreadArrays = (this && this.__spreadArrays) || function () {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};
Object.defineProperty(exports, "__esModule", { value: true });
var child_process_1 = require("child_process");
var lodash_1 = require("lodash");
// isRoot returns if the current running user is the root user.
exports.isRoot = function () {
    // We only check if we are root in the ADB setting
    var commandResult = exports.shell(["id"], true);
    if (commandResult.status === 0) {
        if (commandResult.output[1].toString().search("uid=0") < 0 &&
            commandResult.output[1].toString().search("(root)") < 0) {
            return true;
        }
    }
    return false;
};
// adbShell is a shell function that can be used with ADB.
exports.adbShell = function (command, isRoot) {
    return child_process_1.spawnSync("adb", __spreadArrays(["shell"], (isRoot ? ["su", "-c"] : []), command));
};
// shell is a generic shell command that can be used for both ADB and linux.
exports.shell = function (command, adb) {
    if (adb) {
        return exports.adbShell(command, exports.memoIsRoot());
    }
    var args = command.length === 1 ? [] : command.slice(1, command.length);
    return child_process_1.spawnSync(command[0], args);
};
// resolveFileDescriptor uses the readlink command to resolve the symbolic
// links of the proc filesystem to get the driver name that proc is sending
// syscalls to. Note that this is probably not super accurate.
exports.resolveFileDescriptor = function (pid, fd, adb) {
    var commandResult = exports.shell(["readlink", "/proc/" + pid + "/fd/" + fd], adb);
    if (commandResult.status === 0 && commandResult.output.length >= 2) {
        return commandResult.output[1].toString().trim();
    }
    return null;
};
// During the course of running this tool, it's likely these
// values will not change. The file descriptor resolution might
// so keep an eye on that one.
exports.memoIsRoot = lodash_1.memoize(exports.isRoot);
exports.memoResolveFileDescriptor = lodash_1.memoize(exports.resolveFileDescriptor);
