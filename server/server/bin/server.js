"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const process = require("process");
const frida_helper_1 = require("./frida_helper");
const express = require("express");
const expressWs = require("express-ws");
const app = express();
const ws = expressWs(app);
class DapServer {
    constructor(port = 8888) {
        this.currentEventId = 0;
        this.syscallEvents = [];
        this.fridaHelper = null;
        process.on('SIGTERM', this.stop.bind(this));
        process.on('SIGINT', this.stop.bind(this));
        app.ws('/event-stream', (ws, req) => {
            this.emitLatestEvents();
            ws.on('message', (msg) => {
                // ws.send(msg);
            });
        });
        app.get('/events', (req, res) => {
            // TODO: Don't hardcode CORS whitelist
            res.set('Access-Control-Allow-Origin', 'http://localhost:3000');
            res.send(this.syscallEvents);
            this.syscallEvents = [];
        });
    }
    start(port = 8888) {
        app.listen(port, () => console.log(`started server on port ${port}`));
    }
    attach(targetProcess, adb) {
        return __awaiter(this, void 0, void 0, function* () {
            this.fridaHelper = new frida_helper_1.FridaHelper(targetProcess, adb);
            this.fridaHelper.startSession()
                .then(() => {
                return this.fridaHelper.attachScript('./bin/ioctler.js', this.handleFridaEvent.bind(this));
            })
                .catch((e) => {
                console.error(`frida attach error: ${e}`);
                console.error(e.stack);
                this.stop();
            });
        });
    }
    stop() {
        return __awaiter(this, void 0, void 0, function* () {
            console.debug('quitting');
            if (!!this.fridaHelper) {
                this.fridaHelper.stop();
            }
            process.exit(0);
        });
    }
    handleFridaEvent(message, data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!message) {
                return;
            }
            if (message.type === 'send' && message.payload.syscall === 'ioctl') {
                message.payload.id = this.currentEventId++;
                if (!!data) {
                    message.payload.data = JSON.parse(JSON.stringify(data)).data;
                }
                if (!message.payload.driverName) {
                    try {
                        message.payload.driverName = this.fridaHelper.resolveFileDescriptor(message.payload.fd);
                        if (!!message.payload.driverName) {
                            yield this.fridaHelper.setFD(message.payload.fd, message.payload.driverName);
                        }
                        else {
                            message.payload.driverName = `<unknown:${message.payload.fd}>`;
                        }
                    }
                    catch (error) {
                        message.payload.driverName = `<unknown:${message.payload.fd}>`;
                        console.log(error);
                    }
                }
                this.syscallEvents.push(message.payload);
            }
            else if (message.type === 'error') {
                console.log('error', message);
            }
        });
    }
    emitLatestEvents() {
        if (this.syscallEvents.length > 0) {
            ws.getWss().clients.forEach((client) => __awaiter(this, void 0, void 0, function* () {
                client.send(JSON.stringify(this.syscallEvents));
            }));
            this.syscallEvents = [];
        }
        setTimeout(this.emitLatestEvents.bind(this), 1000);
    }
}
DapServer.EVENT_OPEN = 'open';
DapServer.EVENT_SOCKET = 'socket';
DapServer.EVENT_CLOSE = 'close';
DapServer.EVENT_IOCTL = 'ioctl';
exports.DapServer = DapServer;
//# sourceMappingURL=server.js.map