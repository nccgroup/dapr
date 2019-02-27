(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
'use strict';

rpc.exports = {
  initFDs: function (fdMap) {
    initFDs(fdMap);
  },
  getFDs: function () {
    return files;
  },
  installHooks: function () {
    installHooks();
  },
  setFD: function (fd, path) {
    files[fd] = path;
  },
  getFD: function (fd) {
    return fd in files ? files[fd] : null;
  }
};
var files = {}; //const fs = require('frida-fs');

const _IOC_NRBITS = 8;

const _IOC_NRMASK = (1 << _IOC_NRBITS) - 1;

const EVENT_OPEN = 'open';
const EVENT_SOCKET = 'socket';
const EVENT_CLOSE = 'close';
const EVENT_IOCTL = 'ioctl';

var initFDs = function (fdMap) {
  files = fdMap;
};

var IoctlEvent = function (fd, driverName, mode, size, opcode, request, retval, start, end) {
  return {
    syscall: EVENT_IOCTL,
    fd: fd,
    driverName: driverName,
    mode: mode,
    size: size,
    opcode: opcode,
    request: request,
    data: null,
    retval: retval,
    start: start,
    end: end
  };
};

var OpenEvent = function (driverName, mode, retval, start, end) {
  return {
    syscall: EVENT_OPEN,
    driverName: driverName,
    mode: mode,
    retval: retval,
    start: start,
    end: end
  };
};

var SocketEvent = function (domain, type, protocol, retval, start, end) {
  return {
    syscall: EVENT_SOCKET,
    domain: domain,
    type: type,
    protocol: protocol,
    retval: retval,
    start: start,
    end: end
  };
};

var CloseEvent = function (fd, driverName, retval, start, end) {
  return {
    syscall: EVENT_CLOSE,
    fd: fd,
    driverName: driverName,
    retval: retval,
    start: start,
    end: end
  };
};

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
  threads.forEach(function (thread) {
    console.log('[thread] id:' + thread.id + ' state:' + thread.state);
  });
} catch (e) {
  console.log(e.stack);
}

function installGenericOpenHook(library, func) {
  Interceptor.attach(Module.findExportByName(library, func), {
    onLeave: function (retval) {
      const ret = parseInt(retval);

      if (ret >= 0) {
        const end = new Date().getTime();
        const event = OpenEvent('anon_inode:[' + func + ']', 'r', ret, 0, 0, end);
        send(event);
      }

      return retval;
    }
  });
}

function installHooks() {
  Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function (args) {
      this.start = new Date().getTime();
      this.fd = parseInt(args[0]);
      this.driverName = this.fd in files ? files[this.fd] : null;

      if (!this.driverName) {//console.log('[+ioctl] ' + this.fd);
      }

      this.request = parseInt(args[1]);
      this.opcode = this.request & 0xff;
      this.chr = this.request >> 8 & 0xff;
      this.size = this.request >> 16 & (1 << 0xe) - 1;
      this.modebits = this.request >> 30 & (1 << 0x2) - 1;
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
      const end = new Date().getTime();
      const event = IoctlEvent(this.fd, this.driverName, this.mode, this.size, this.opcode, this.request.toString(16), parseInt(retval), this.start, end);

      if (!this.driverName) {
        this.driverName = this.fd in files ? files[this.fd] : null; //console.log('[-ioctl] ', this.fd, this.driverName);
      }

      if (this.data instanceof Object) {
        send(event, this.data);
      } else {
        send(event, null);
      }

      return retval;
    }
  });
  Interceptor.attach(Module.findExportByName(null, "close"), {
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
      const event = CloseEvent(this.fd, driverName, parseInt(retval), this.start, end);
      send(event);
      return retval;
    }
  });
  Interceptor.attach(Module.findExportByName(null, "open"), {
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
      const event = OpenEvent(this.driverName, this.mode, retval, this.start, end);
      send(event);
      return retval;
    }
  });
  Interceptor.attach(Module.findExportByName(null, "openat"), {
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
      const event = OpenEvent(this.driverName, this.mode, retval, this.start, end);
      send(event);
      return retval;
    }
  });
  Interceptor.attach(Module.findExportByName(null, "socket"), {
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
      const event = SocketEvent(this.domain, this.type, this.protocol, retval, this.start, end);
      send(event);
      return retval;
    }
  });
  installGenericOpenHook(null, "dup");
  installGenericOpenHook(null, "dup2");
  installGenericOpenHook(null, "dup3");
  installGenericOpenHook(null, "epoll_create");
  installGenericOpenHook(null, "epoll_create1");
  installGenericOpenHook(null, "eventfd");
  installGenericOpenHook(null, "inotify_init");
  installGenericOpenHook(null, "signalfd");
  installGenericOpenHook(null, "timerfd_create");
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

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJmcmlkYS1zY3JpcHRzL2lvY3RsZXIuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7QUNBQTs7QUFFQSxHQUFHLENBQUMsT0FBSixHQUFjO0FBQ1osRUFBQSxPQUFPLEVBQUUsVUFBUyxLQUFULEVBQWdCO0FBQ3ZCLElBQUEsT0FBTyxDQUFDLEtBQUQsQ0FBUDtBQUNELEdBSFc7QUFJWixFQUFBLE1BQU0sRUFBRSxZQUFXO0FBQ2pCLFdBQU8sS0FBUDtBQUNELEdBTlc7QUFPWixFQUFBLFlBQVksRUFBRSxZQUFZO0FBQ3hCLElBQUEsWUFBWTtBQUNiLEdBVFc7QUFVWixFQUFBLEtBQUssRUFBRSxVQUFVLEVBQVYsRUFBYyxJQUFkLEVBQW9CO0FBQ3pCLElBQUEsS0FBSyxDQUFDLEVBQUQsQ0FBTCxHQUFZLElBQVo7QUFDRCxHQVpXO0FBYVosRUFBQSxLQUFLLEVBQUUsVUFBVSxFQUFWLEVBQWM7QUFDbkIsV0FBTyxFQUFFLElBQUksS0FBTixHQUFjLEtBQUssQ0FBQyxFQUFELENBQW5CLEdBQTBCLElBQWpDO0FBQ0Q7QUFmVyxDQUFkO0FBa0JBLElBQUksS0FBSyxHQUFHLEVBQVosQyxDQUVBOztBQUVBLE1BQU0sV0FBVyxHQUFHLENBQXBCOztBQUNBLE1BQU0sV0FBVyxHQUFJLENBQUMsS0FBSyxXQUFOLElBQW1CLENBQXhDOztBQUVBLE1BQU0sVUFBVSxHQUFHLE1BQW5CO0FBQ0EsTUFBTSxZQUFZLEdBQUcsUUFBckI7QUFDQSxNQUFNLFdBQVcsR0FBRyxPQUFwQjtBQUNBLE1BQU0sV0FBVyxHQUFHLE9BQXBCOztBQUVBLElBQUksT0FBTyxHQUFHLFVBQVMsS0FBVCxFQUFnQjtBQUM1QixFQUFBLEtBQUssR0FBRyxLQUFSO0FBQ0QsQ0FGRDs7QUFJQSxJQUFJLFVBQVUsR0FBRyxVQUFTLEVBQVQsRUFBYSxVQUFiLEVBQXlCLElBQXpCLEVBQStCLElBQS9CLEVBQXFDLE1B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V0FBSyxNQUFMLEdBQWMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFELENBQUwsQ0FBdEI7QUFDQSxXQUFLLElBQUwsR0FBWSxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUQsQ0FBTCxDQUFwQjtBQUNBLFdBQUssUUFBTCxHQUFnQixRQUFRLENBQUMsSUFBSSxDQUFDLENBQUQsQ0FBTCxDQUF4QjtBQUNBLGFBQU8sQ0FBUDtBQUNELEtBUEg7QUFRRSxJQUFBLE9BQU8sRUFBRSxVQUFVLE1BQVYsRUFBa0I7QUFDekIsTUFBQSxNQUFNLEdBQUcsUUFBUSxDQUFDLE1BQUQsQ0FBakI7O0FBQ0EsVUFBSSxNQUFNLElBQUksQ0FBZCxFQUFpQjtBQUNmLFFBQUEsS0FBSyxDQUFDLE1BQUQsQ0FBTCxHQUFnQixZQUFZLEtBQUssTUFBakIsR0FBMEIsR0FBMUIsR0FBZ0MsS0FBSyxJQUFyQyxHQUE0QyxHQUE1QyxHQUFrRCxLQUFLLFFBQXZFO0FBQ0Q7O0FBQ0QsWUFBTSxHQUFHLEdBQUcsSUFBSSxJQUFKLEdBQVcsT0FBWCxFQUFaO0FBQ0EsWUFBTSxLQUFLLEdBQUcsV0FBVyxDQUN2QixLQUFLLE1BRGtCLEVBRXZCLEtBQUssSUFGa0IsRUFHdkIsS0FBSyxRQUhrQixFQUl2QixNQUp1QixFQUt2QixLQUFLLEtBTGtCLEVBTXZCLEdBTnVCLENBQXpCO0FBT0EsTUFBQSxJQUFJLENBQUMsS0FBRCxDQUFKO0FBQ0EsYUFBTyxNQUFQO0FBQ0Q7QUF2QkgsR0FERjtBQTJCQSxFQUFBLHNCQUFzQixDQUFDLElBQUQsRUFBTyxLQUFQLENBQXRCO0FBQ0EsRUFBQSxzQkFBc0IsQ0FBQyxJQUFELEVBQU8sTUFBUCxDQUF0QjtBQUNBLEVBQUEsc0JBQXNCLENBQUMsSUFBRCxFQUFPLE1BQVAsQ0FBdEI7QUFDQSxFQUFBLHNCQUFzQixDQUFDLElBQUQsRUFBTyxjQUFQLENBQXRCO0FBQ0EsRUFBQSxzQkFBc0IsQ0FBQyxJQUFELEVBQU8sZUFBUCxDQUF0QjtBQUNBLEVBQUEsc0JBQXNCLENBQUMsSUFBRCxFQUFPLFNBQVAsQ0FBdEI7QUFDQSxFQUFBLHNCQUFzQixDQUFDLElBQUQsRUFBTyxjQUFQLENBQXRCO0FBQ0EsRUFBQSxzQkFBc0IsQ0FBQyxJQUFELEVBQU8sVUFBUCxDQUF0QjtBQUNBLEVBQUEsc0JBQXNCLENBQUMsSUFBRCxFQUFPLGdCQUFQLENBQXRCO0FBQ0Q7QUFFRCIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
