'use strict';

const _ = require('lodash');

rpc.exports = {
  init: function(fdMap) {
    initLibC();
    initFDs(fdMap);
    installHooks();
  },

  getFDs: function() {
    return files;
  },
  setFD: function (fd, path) {
    files[fd] = path;
  },
  getFD: function (fd) {
    return fd in files ? files[fd] : null;
  },

  inject: function(syscalls) {
    var results = [];
    syscalls.forEach(function (syscall) {
      switch (syscall.syscall) {
        case 'ioctl':
          var result = injectIoctl(syscall.fd, syscall.request, syscall.data);
          results.push(result);
          break;
        default:
          throw new Error('Unknown syscall');
      }
    });
    return results;
  },

  blacklistGetAll() {
    return blacklist;
  },
  blacklistGet(index) {
    validateBlacklistIndex(index);
    return blacklist[index];
  },
  blacklistPut(matcher) {
    validateFieldMatcher(matcher);
    blacklist.push(matcher);
    return (blacklist.length - 1);
  },
  blacklistUpdate(index, matcher) {
    validateBlacklistIndex(index);
    validateFieldMatcher(matcher);
    blacklist[index] = matcher;
    return {};
  },
  blacklistDelete(index) {
    validateBlacklistIndex();
    blacklist[index] = null;
    return {};
  },

  typeGetAll() {
    return types;
  },
  typeGet(index) {
    validateTypeIndex(index);
    return types[index];
  },
  typePut(type) {
    validateType(type);
    types.push(type);
    return (types.length - 1);
  },
  typeUpdate(index, type) {
    validateTypeIndex(index);
    validateType(type);
  },
  typeDelete(index) {
    validateTypeIndex(index);
  },

  typeAssignGetAll() {
    return typeAssignments;
  },
  typeAssignGet(index) {
    validateAssignIndex(index);
    return typeAssignments[index];
  },
  typeAssignPut(typeIndex, matcher) {
    validateTypeIndex(typeIndex);
    validateFieldMatcher(matcher);
    const typeAssignment = {
      typeId: typeIndex,
      matcher: matcher
    };
    typeAssignments.push(typeAssignment);
    return (typeAssignments.length - 1);
  },
  typeAssignUpdate(index, typeIndex, matcher) {
    validateAssignIndex(index);
    validateTypeIndex(typeIndex);
    validateFieldMatcher(matcher);
    const typeAssignment = {
      typeId: typeIndex,
      matcher: matcher
    };
    typeAssignments[index] = typeAssignment;
  },
  typeAssignDelete(index) {
    validateAssignIndex(index);
    typeAssignments[index] = null;
  }
};

const _IOC_NRBITS = 8;
const _IOC_NRMASK = ((1 << _IOC_NRBITS)-1);

var libc = null;
const ioctl = new NativeFunction(Module.findExportByName(libc, 'ioctl'), 'int', ['int', 'ulong', '...', 'pointer']);

var files = {};
var blacklist = [];
var whitelist = [];
var types = [];
var typeAssignments = [];

function initLibC() {
  var modules = Process.enumerateModulesSync();
  for (var i = 0; i < modules.length; i++) {
    if (!!modules[i].name.match(/^libc[\.\-]/)) {
      libc = modules[i].name;
      console.log('found libc: ' + libc);
    }
  }
}

function validateBlacklistIndex(index) {
  if (blacklist.length === 0 || index < 0 || index >= blacklist.length) {
    throw new Error('Bad blacklist item ID');
  }
}

function validateFieldMatcher(matcher) {
  if (!matcher.hasOwnProperty('field') || !matcher.hasOwnProperty('value')) {
    throw new Error('Bad EventMatcher definition');
  }
  if (matcher.regex === true) {
    if ((typeof matcher.value) !== 'string') {
      throw new Error('Bad regular expression');
    }
  }
}

function validateTypeIndex(index) {
  if (index === null || index === undefined || types.length === 0 || index < 0 || index >= types.length) {
    throw new Error('Bad type ID');
  }
}

function validateType(type) {
  const requiredFields = ['name', 'fields'];
  var isValid = _.every(requiredFields, function (f) {
    return (type.hasOwnProperty(f) && type[f] !== undefined);
  });
  if (!isValid) {
    throw new Error('Invalid StructDef');
  }
  type.fields.forEach(function (field) {
    validateField(field);
  });
}

function validateField(field) {
  const requiredFields = ['name', 'type', 'width', 'lengthExpression', 'isArray', 'isSigned', 'isPointer', 'isEventLength', 'isNullTerminatedString'];
  var isValid = _.every(requiredFields, function (f) {
    return (field.hasOwnProperty(f) && field[f] !== undefined);
  });
  if (!isValid) {
    throw new Error('Invalid FieldDef');
  }
}

function validateAssignIndex(index) {
  if (index === null || index === undefined || typeAssignments.length === 0 || index < 0 || index >= typeAssignments.length) {
    throw new Error('Bad type assignment ID');
  }
}


function injectIoctl(fd, request, data) {
  var _request = (typeof request === 'string')
    ? parseInt(request, 16)
    : request;
  var _data;

  if (!!data) {
    var _data = Memory.alloc(data.length);
    Memory.writeByteArray(_data, data, data.length);
  } else {
    _data = ptr('0x0');
  }

  var ret = ioctl(fd, _request, _data);

  var outData = null;
  if (!!data) {
    var outData = Array.prototype.slice.call(new Uint8Array(Memory.readByteArray(_data, data.length)));
  }

  return { retval: ret, data: outData };
}

var initFDs = function(fdMap) {
  files = fdMap;
};

var IoctlEvent = function(fd, driverName, mode, size, opcode, request, retval, start, end) {
  return {
    syscall: 'ioctl',
    fd: fd,
    driverName: driverName,
    mode: mode,
    size: size,
    opcode: opcode,
    request: request,
    data: null,
    retval: retval,
    start: start,
    end: end,
  };
}

var OpenEvent = function(driverName, mode, retval, start, end) {
  return {
    syscall: 'open',
    driverName: driverName,
    mode: mode,
    retval: retval,
    start: start,
    end: end,
  };
}

var SocketEvent = function(domain, type, protocol, retval, start, end) {
  return {
    syscall: 'socket',
    domain: domain,
    type: type,
    protocol: protocol,
    retval: retval,
    start: start,
    end: end,
  };
}

var CloseEvent = function(fd, driverName, retval, start, end) {
  return {
    syscall: 'close',
    fd: fd,
    driverName: driverName,
    retval: retval,
    start: start,
    end: end,
  };
}

function getRandomInt(max) {
  return Math.floor(Math.random() * Math.floor(max));
}
function generateId() {
  return getRandomInt(100000000000);
}

try {
  console.log('[debugger?] ' + Process.isDebuggerAttached());
  console.log('[current thread] ' + Process.getCurrentThreadId());
  const threads = Process.enumerateThreadsSync();
  threads.forEach(function(thread) {
    console.log('[thread] id:'+thread.id+' state:'+thread.state);
  });
} catch (e) {
  console.log(e.stack);
}

function installGenericOpenHook(library, func) {
  Interceptor.attach(Module.findExportByName(library, func),
    {
      onLeave: function (retval) {
        const ret = parseInt(retval);
        if (ret >= 0) {
          const end = new Date().getTime();
          const event = OpenEvent(
            'anon_inode:[' + func + ']',
            'r',
            ret,
            0,
            0,
            end);
          send(event);
        }
        return retval;
      }
    });
}

function getTypeFor(event) {
  var result = null;
  var matchedTA = null;
  for (var i = 0; i < typeAssignments.length; ++i) {
    var ta = typeAssignments[i];
    if (ta.matcher.regex === true) {
      const regex = new RegExp(ta.matcher.value);
      if (!!regex.exec(event[ta.matcher.field])) {
        matchedTA = ta;
        break;
      }
    } else if (event[ta.matcher.field] === ta.matcher.value) {
      matchedTA = ta;
      break;
    }
  }
  if (!!matchedTA) {
    result = types[ta.typeId];
  }
  return result;
}

function shouldBlacklist(event) {
  var result = false;
  blacklist.forEach(function (matcher) {
    if (!matcher) {
      return;
    }
    if (matcher.regex === true) {
      const regex = new RegExp(matcher.value);
      if (!!regex.exec(event[matcher.field])) {
        result = true;
      }
    } else {
      if (event[matcher.field] === matcher.value) {
        result = true;
      }
    }
  });
  return result;
}

function shouldWhitelist(event) {
  // TODO: Implement whitelist API
  return false;
}

function installHooks() {

  Interceptor.attach(Module.findExportByName(libc, "ioctl"),
    {
      onEnter: function (args) {
        this.ignore = false;
        this.start = new Date().getTime();
        this.fd = parseInt(args[0]);
        this.driverName = this.fd in files ? files[this.fd] : null;
        if (!this.driverName) {
          //console.log('[+ioctl] ' + this.fd);
        }
        this.request = parseInt(args[1]);
        this.opcode = this.request & 0xff;
        this.chr = (this.request >> 8) & 0xff;
        this.size = (this.request >> 16) & ((1 << 0xe) - 1);
        this.modebits = (this.request >> 30) & ((1 << 0x2) - 1);
        this.mode = '';
        switch (this.modebits) {
          case 0:
            this.mode = '?';
            break;
          case 1:
            this.mode = 'w';
            break;
          case 2:
            this.mode = 'r';
            break;
          case 3:
            this.mode = 'rw';
            break;
        }

        if (!shouldWhitelist(this)) {
          if (shouldBlacklist(this)) {
            this.ignore = true;
            return 0;
          }
        }

        var type = getTypeFor(this);
        /* TODO: Applies special attributes from the type to the event
                  - isNullTerminated
                  - lengthExpression
                  - isEventLength
                  - probably other things too */

        this.data = null;
        if (this.size > 0) {
          try {
            this.data = Memory.readByteArray(args[2], this.size);
          } catch (e) {
            this.data = parseInt(args[2]);
          }
          /*
          console.log(hexdump(arg, {
              offset: 0,
              length: size,
              header: false,
              ansi: true
          }));
          */
        }
        return 0;
      },
      onLeave: function (retval) {
        if (this.ignore) {
          return retval;
        }
        const end = new Date().getTime();
        const event = IoctlEvent(
          this.fd,
          this.driverName,
          this.mode,
          this.size,
          this.opcode,
          this.request.toString(16),
          parseInt(retval),
          this.start, end);
        if (!this.driverName) {
          this.driverName = this.fd in files ? files[this.fd] : null;
          //console.log('[-ioctl] ', this.fd, this.driverName);
        }
        if (this.data instanceof Object) {
          send(event, this.data);
        } else {
          send(event, null);
        }
        return retval;
      }
    });

  Interceptor.attach(Module.findExportByName(libc, "close"),
    {
      onEnter: function (args) {
        this.start = new Date().getTime();
        this.fd = parseInt(args[0]);
        return 0;
      },
      onLeave: function (retval) {
        retval = parseInt(retval);
        var driverName = null;
        if (retval >= 0) {
          if (this.fd in files) {
            driverName = files[this.fd];
            delete files[this.fd];
          }
        }
        const end = new Date().getTime();
        const event = CloseEvent(
          this.fd,
          driverName,
          parseInt(retval),
          this.start,
          end);
        send(event);
        return retval;
      }
    });

  Interceptor.attach(Module.findExportByName(libc, "open"),
    {
      onEnter: function (args) {
        this.start = new Date().getTime();
        this.driverName = Memory.readCString(args[0]);
        this.mode = args[1];
        return 0;
      },
      onLeave: function (retval) {
        retval = parseInt(retval);
        if (retval >= 0) {
          files[retval] = this.driverName;
        }
        const end = new Date().getTime();
        const event = OpenEvent(
          this.driverName,
          this.mode,
          retval,
          this.start,
          end);
        send(event);
        return retval;
      }
    });

  Interceptor.attach(Module.findExportByName(libc, "openat"),
    {
      onEnter: function (args) {
        this.start = new Date().getTime();
        this.driverName = 'openat:' + Memory.readCString(args[1]);
        this.mode = 'r'; // HACK
        return 0;
      },
      onLeave: function (retval) {
        retval = parseInt(retval);
        if (retval >= 0) {
          files[retval] = this.driverName;
        }
        const end = new Date().getTime();
        const event = OpenEvent(
          this.driverName,
          this.mode,
          retval,
          this.start,
          end);
        send(event);
        return retval;
      }
    });

  Interceptor.attach(Module.findExportByName(libc, "socket"),
    {
      onEnter: function (args) {
        this.start = new Date().getTime();
        this.domain = parseInt(args[0]);
        this.type = parseInt(args[1]);
        this.protocol = parseInt(args[2]);
        return 0;
      },
      onLeave: function (retval) {
        retval = parseInt(retval);
        if (retval >= 0) {
          files[retval] = 'socket:' + this.domain + ':' + this.type + ':' + this.protocol;
        }
        const end = new Date().getTime();
        const event = SocketEvent(
          this.domain,
          this.type,
          this.protocol,
          retval,
          this.start,
          end);
        send(event);
        return retval;
      }
    });

  installGenericOpenHook(libc, "dup");
  installGenericOpenHook(libc, "dup2");
  installGenericOpenHook(libc, "dup3");
  installGenericOpenHook(libc, "epoll_create");
  installGenericOpenHook(libc, "epoll_create1");
  installGenericOpenHook(libc, "eventfd");
  installGenericOpenHook(libc, "inotify_init");
  installGenericOpenHook(libc, "signalfd");
  installGenericOpenHook(libc, "timerfd_create");
}

/*
try {
    const maps = fs.readFileSync('/proc/self/maps', 'utf8');
    console.log(maps);
} catch(e) {
    console.log(e);
    console.log(e.stack);
}
try {
    const fds = fs.readdirSync('/proc/self/fd/');
    fds.forEach(function(fd) {
        if (isNaN(fd)) {
            return;
        }
        var driverName = '/proc/self/fd/'+fd;
        var link = fs.readlinkSync(driverName);
        console.log(fd+':'+link);
    });
} catch(e) {
    console.log(e.stack);
}
for (var fd=0; fd<100; ++fd) {
    try {
        var driverName = '/proc/self/fd/'+fd;
        var link = fs.readlinkSync(driverName);
        console.log(fd+':'+link);
    } catch(e) {
        console.log(e.stack);
    }
}
*/

