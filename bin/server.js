"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const process = require("process");
const frida_session_1 = require("./frida_session");
const express = require("express");
const expressWs = require("express-ws");
const bodyParser = require("body-parser");
const cors = require("cors");
const app = express();
const ws = expressWs(app);
class DapServer {
    constructor(port) {
        this.currentEventId = 0;
        this.syscallEvents = [];
        this.fridaSession = null;
        this.port = 0;
        this.server = null;
        this.lastEmittedIndex = 0;
        process.on('SIGTERM', this.quit.bind(this));
        process.on('SIGINT', this.quit.bind(this));
        this.port = port;
        setInterval(this.emitLatestEvents.bind(this), 1000);
        app.use(bodyParser.json());
        // TODO: Remove CORS header once we serve the UI from the same origin as the server.
        app.use(cors({ origin: 'http://localhost:3000' }));
        app.use((req, res, next) => {
            if (req.headers.host !== `localhost:${this.port}` &&
                req.headers.host !== `127.0.0.1:${this.port}`) {
                next('DNS rebinding attack blocked');
            }
            else {
                next();
            }
        });
        /*
        # API Definition
        GET /session/status
    
        # Description
        Returns the current state of the Frida session. Poll this API after doing an `attach` or `detach`. When the status
        is "attached", the process ID is also returned.
    
        # Request Body Parameters
        N/A
    
        # Response Body
        status: string
        pid: Integer or Undefined
        */
        app.get('/session/status', (req, res) => {
            const out = {};
            if (!this.fridaSession) {
                out.status = 'detached';
            }
            else {
                switch (this.fridaSession.status) {
                    case frida_session_1.SessionStatus.ATTACHED:
                        out.status = 'attached';
                        out.pid = this.fridaSession.session.pid;
                        break;
                    case frida_session_1.SessionStatus.FAILED:
                        out.status = 'failed';
                        out.reason = this.fridaSession.reason.message.toString();
                        break;
                    case frida_session_1.SessionStatus.PENDING:
                        out.status = 'pending';
                        break;
                    case frida_session_1.SessionStatus.DETACHED:
                        out.status = 'detached';
                        break;
                    default:
                        throw new Error('unknown status');
                }
            }
            res.send(out);
        });
        app.use('/*', (req, res, next) => {
            if (!!this.fridaSession && this.fridaSession.status === frida_session_1.SessionStatus.PENDING) {
                res.status(500).send('Operation pending');
                res.end();
            }
            else {
                next();
            }
        });
        /*
        # API Definition
        POST /session/attach
    
        # Description
        Asynchronously attaches Frida to a `target` process, which can be either a process ID or process name. On success,
        Dapr begins hooking system calls and streams events to websocket clients.
    
        Note: The result of this operation can be checked by polling /session/status.
    
        # Request Body Parameters
        target: Integer | String      - process ID or process name
        */
        app.post('/session/attach', (req, res) => {
            const { target, adb } = req.body;
            try {
                this.attach(target, adb);
                res.send();
            }
            catch (e) {
                res.status(500).send(e.toString());
            }
        });
        app.use('/*', (req, res, next) => {
            if (!this.fridaSession || this.fridaSession.status !== frida_session_1.SessionStatus.ATTACHED) {
                res.status(500).send('Must be attached');
                res.end();
            }
            else {
                next();
            }
        });
        /*
        # API Definition
        POST /session/detach
    
        # Description
        Detach from a Frida session.
    
        Note: The result of this operation can be checked by polling /session/status.
        */
        app.post('/session/detach', (req, res, next) => {
            console.log(`detaching from ${this.fridaSession.session.pid}`);
            try {
                this.detach();
                res.send();
            }
            catch (e) {
                res.status(500).send(e.toString());
            }
        });
        /*
        # API Definition
        GET /last-event
    
        # Description
        Returns the index/id of the event last emitted over websocket or via `GET /events`.
    
        # Response Body
        index: Integer
        */
        app.get('/last-event', (req, res) => {
            res.send({ index: this.lastEmittedIndex });
        });
        /*
        # API Definition
        Websocket Event Stream
    
        # Description
        If a session is attached, the server streams an array of the most recent events every second.
    
        # Response Body
        [Event, ...]
    
        # Types
        Event:
          id: Integer             - Incremental ID of the event
          syscall: String         - Only "ioctl" for now
          fd: Integer             - file descriptor
          driverName: String      - e.g. "/dev/binder"
          mode: String            - "mode" field encoded within of ioctl `request` argument
          size: Integer           - "size" field encoded within of ioctl `request` argument
          opcode: Integer         - "opcode" field encoded within of ioctl `request` argument
          request: String         - The second argument `request` argument of the ioctl syscall
          data: null | Integer[]  - Byte-array of request data, i.e. the third argument of the ioctl syscall
          retval: Integer         - Return value of the ioctl syscall
          start: Integer          - Timestamp of when the ioctl request started
          end: Integer            - Timestamp of when the ioctl request finished
        */
        app.ws('/event-stream', (ws, req) => {
            ws.on('message', (msg) => {
                // ws.send(msg);
            });
        });
        /*
        # API Definition
        GET /events
    
        # Description
        An HTTP/RESTful version of the websocket streaming API.
    
        # Response Body
        [Event, ...]
        */
        app.get('/events', (req, res) => {
            res.send(this.syscallEvents.slice(this.lastEmittedIndex, this.syscallEvents.length));
            this.lastEmittedIndex = this.syscallEvents.length;
        });
        /*
        # API Definition
        GET /events/:id
    
        # Description
        Returns an event for a given id, which is an index into an array of events.
    
        # Path Parameters
        id: Integer     - The index of an event
    
        # Response Body
        [Event]
        */
        app.get('/events/:index', (req, res) => {
            const index = parseInt(req.params.index, 10);
            if (index < 0 || index >= this.syscallEvents.length) {
                res.status(500).send('Invalid index');
            }
            else {
                res.send(this.syscallEvents[index]);
            }
        });
        /*
        # API Definition
        GET /events/range/:begin
    
        # Description
        Returns a range of events starting at a given index.
    
        # Path Parameters
        begin: Integer     - The beginning event index
    
        # Response Body
        [Event, ...]
        */
        app.get('/events/range/:begin', (req, res) => {
            const begin = parseInt(req.params.begin, 10);
            if (begin < 0 || begin >= this.syscallEvents.length) {
                res.status(500).send('Invalid range');
            }
            else {
                res.send(this.syscallEvents.slice(begin, this.syscallEvents.length));
            }
        });
        /*
        # API Definition
        GET /events/range/:begin/:end
    
        # Description
        Returns a range of events beginning and ending at the given indices.
    
        # Path Parameters
        begin: Integer     - The beginning event index
        end: Integer       - The end event index
    
        # Response Body
        [Event, ...]
        */
        app.get('/events/range/:begin/:end', (req, res) => {
            const begin = parseInt(req.params.begin, 10);
            const end = parseInt(req.params.end, 10);
            if (begin < 0 || begin >= this.syscallEvents.length ||
                end < 0 || end >= this.syscallEvents.length ||
                end < begin) {
                res.status(500).send('Invalid range');
            }
            else {
                res.send(this.syscallEvents.slice(begin, end));
            }
        });
        /*
        # API Definition
        POST /events
    
        # Description
        Synchronously inject a series of events into the target process.
    
        # Request Body Parameters
        [InjectInput, ...]
    
        # Response Body
        [InjectOutput, ...]
    
        # Types
        InjectInput:
          syscall: String           - "ioctl" for now
          fd: Integer               - first arg of ioctl syscall
          request: String | Integer - second arg of ioctl syscall; hex-encoded string or raw integer value
          data: Integer[] | null    - third arg of ioctl syscall; byte-array of data or null
    
        InjectOutput:
          data: Integer[] | null    - third arg of ioctl syscall; may be populated with output data from the target driver.
          retval: Integert          - return value of the ioctl syscall
        */
        app.post('/events', (req, res, next) => {
            const syscalls = req.body;
            if (!syscalls || syscalls.length === 0 || syscalls.constructor !== Array) {
                res.status(500).send('Bad input');
            }
            else {
                this.fridaSession.inject(syscalls)
                    .then((results) => {
                    res.send(results);
                })
                    .catch((e) => {
                    res.status(500).send(e.toString());
                });
            }
        });
        /*
        # API Definition
        GET /blacklist
    
        # Description
        Returns all blacklisted EventMatchers.
    
        Note: The purpose of the blacklist is to let the user filter out events that they do not want to see. This improves
              performance because irrelevant events do not need to be shuffled across process/device boundaries and rendered
              in the UI.
    
              Users submit an "EventMatcher" which are used to tag events where a field matches a certain value. For
              example, to blacklist all events for the driver /dev/binder, you would need an event matcher where the field
              is "driverName" is "/dev/binder".
    
        # Response Body
        [EventMatcher, ...]
    
        # Types
        EventMatcher:
          field: String     - Name of the Event field to match on
          value: String     - Value of the Event field to match on
          regex: boolean    - Value is a regular expression
        */
        app.get('/blacklist', (req, resp) => {
            this.fridaSession.blacklistGetAll()
                .then(result => resp.send(result))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        GET /blacklist/:id
    
        # Description
        Returns a blacklisted EventMatcher of a given ID/index.
    
        # Response Body
        EventMatcher
        */
        app.get('/blacklist/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.blacklistGet(id)
                .then(res => resp.send(res))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /blacklist
    
        # Description
        Put an EventMatcher in the blacklist
    
        # Request Body Parameters
        EventMatcher
    
        # Response Body
        id: Integer   - id/index of the blacklist item
        */
        app.post('/blacklist', (req, resp) => {
            const matcher = req.body;
            this.fridaSession.blacklistPut(matcher)
                .then(res => resp.send({ id: res }))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /blacklist/:id
    
        # Description
        Update an EventMatcher in the blacklist
    
        # Request Body Parameters
        id: Integer
        matcher: EventMatcher
        */
        app.post('/blacklist/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            const matcher = req.body;
            this.fridaSession.blacklistUpdate(id, matcher)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /blacklist/:id/delete
    
        # Description
        Delete an EventMatcher in the blacklist
    
        # Request Body Parameters
        id: Integer
        */
        app.post('/blacklist/:id/delete', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.blacklistDelete(id)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        GET /types
    
        # Description
        Get all defined types.
    
        Note: The purpose of Types is to define the structure of ioctl request and response data.
    
        # Response Body
        [TypeDef, ...]
    
        # Types
        TypeDef:
          name: String
          fields: [FieldDef, ...]
    
        FieldDef:
          name: String
          type: Integer                       - Base type of the field; (TODO) currently this is one of the value in the
                                                Types enum, but should probably be a string
          width: Integer                      - Width of the field in bits
          lengthExpression: Expression|null   - Set for fields with a dynamic length
          isArray: boolean                    - True for fields that are arrays
          isSigned: boolean                   - True for fields that are signed
          isPointer: boolean                  - True for fields that are pointers
          isEventLength: boolean              - True for fields that define the length of the entire event
          isNullTerminatedString: boolean     - True for fields that should be treated as a null terminated string
    
        Expression:
          parseTree: any                      - Generated when parsing a field that has a dynamic length. The parse tree is
                                                used to evaluate the expression on event data.
        */
        app.get('/types', (req, resp) => {
            this.fridaSession.typeGetAll()
                .then(result => resp.send(result))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        GET /types/:id
    
        # Description
        Get a type at a specified index.
    
        # Path Parameters
        id: Integer
    
        # Response Body
        TypeDef
        */
        app.get('/types/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.typeGet(id)
                .then(res => resp.send(res))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /types
    
        # Description
        Define a new type
    
        # Request Body Parameters
        TypeDef
    
        # Response Body
        id: Integer
        */
        app.post('/types', (req, resp) => {
            const type = req.body;
            this.fridaSession.typePut(type)
                .then(res => resp.send({ id: res }))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /types/:id
    
        # Description
        Update a type definition
    
        # Path Parameters
        id: Integer
    
        # Request Body Parameters
        TypeDef
        */
        app.post('/types/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            const type = req.body;
            this.fridaSession.typeUpdate(id, type)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /types/:id/delete
    
        # Description
        Delete a type definition
    
        # Path Parameters
        id: Integer
        */
        app.post('/types/:id/delete', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.typeDelete(id)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        GET /typesAssignments
    
        # Description
        Get all type assignments.
    
        Note: The purpose of type assignments is to associate a TypeDef with an EventMatcher. For each Event that matches
              the criteria of the EventMatcher, Dapr applies special attributes of the TypeDef, which may alter how Dapr
              handles the event.
    
        # Response Body
        [TypeAssignment, ...]
    
        # Types
        TypeAssignment:
          matcher: Matcher
          typeId: Integer
        */
        app.get('/typeAssignments', (req, resp) => {
            this.fridaSession.typeAssignGetAll()
                .then(result => resp.send(result))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        GET /typesAssignments/:id
    
        # Description
        Get a type assignments for a given id/index.
    
        # Path Parameters
        id: Integer
    
        # Response Body
        TypeAssignment
        */
        app.get('/typeAssignments/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.typeAssignGet(id)
                .then(res => resp.send(res))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /typesAssignments
    
        # Description
        Assign a TypeDef to an EventMatcher.
    
        # Request Body Parameters
        typeId: Integer
        matcher: EventMatcher
    
        # Response Body
        id: Integer        - ID of type assignment
        */
        app.post('/typeAssignments', (req, resp) => {
            const typeId = req.body.typeId;
            const matcher = req.body.matcher;
            this.fridaSession.typeAssignPut(typeId, matcher)
                .then(res => resp.send({ id: res }))
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /typesAssignments/:id
    
        # Description
        Update a TypeAssignment
    
        # Path Parameters
        id: Integer        - ID of type assignment
    
        # Request Body Parameters
        typeId: Integer
        matcher: EventMatcher
        */
        app.post('/typeAssignments/:id', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            const typeId = req.body.typeId;
            const matcher = req.body.matcher;
            this.fridaSession.typeAssignUpdate(id, typeId, matcher)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
        /*
        # API Definition
        POST /typesAssignments/:id/delete
    
        # Description
        Delete a TypeAssignment
    
        # Path Parameters
        id: Integer        - ID of type assignment
        */
        app.post('/typeAssignments/:id/delete', (req, resp) => {
            const id = parseInt(req.params.id, 10);
            this.fridaSession.typeDelete(id)
                .then(() => resp.send())
                .catch(e => resp.status(500).send(e.toString()));
        });
    }
    start() {
        this.server = app.listen(this.port, () => console.log(`started server on port ${this.port}`));
    }
    stop() {
        if (!!this.server) {
            this.server.close();
        }
    }
    attach(target, adb) {
        if (!!this.fridaSession && this.fridaSession.status === frida_session_1.SessionStatus.ATTACHED) {
            throw new Error(`Already attached to pid ${this.fridaSession.session.pid}`);
        }
        this.fridaSession = new frida_session_1.FridaSession(target, adb);
        this.fridaSession.attach(this.handleFridaMessage.bind(this), () => {
            this.lastEmittedIndex = 0;
            this.syscallEvents = [];
        });
    }
    detach() {
        if (!!this.fridaSession) {
            this.fridaSession.detach();
        }
    }
    quit() {
        return __awaiter(this, void 0, void 0, function* () {
            console.debug('quitting');
            this.detach();
            this.stop();
            process.exit(0);
        });
    }
    handleFridaMessage(message, data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!message) {
                return;
            }
            if (message.type === 'send') {
                if (message.payload.syscall !== 'ioctl') {
                    return;
                }
                message.payload.id = this.currentEventId++;
                if (!!data) {
                    message.payload.data = JSON.parse(JSON.stringify(data)).data;
                }
                if (!message.payload.driverName) {
                    message.payload.driverName = `<unknown:${message.payload.fd}>`;
                    /*
                    // TODO: This is too slow. Figure out a better way to resolve file descriptors in real-time.
                    try {
                      message.payload.driverName = this.fridaHelper.resolveFileDescriptor(message.payload.fd);
                      if (!!message.payload.driverName) {
                        await this.fridaHelper.setFD(message.payload.fd, message.payload.driverName);
                      } else {
                        message.payload.driverName = `<unknown:${message.payload.fd}>`;
                      }
                    } catch (error) {
                      message.payload.driverName = `<unknown:${message.payload.fd}>`;
                      console.log(error);
                    }
                    */
                }
                this.syscallEvents.push(message.payload);
            }
            else if (message.type === 'error') {
                console.log('error', JSON.stringify(message));
            }
            else {
                console.log('unknown message', JSON.stringify(message));
            }
        });
    }
    emitLatestEvents() {
        if (ws.getWss().clients === 0 || !this.fridaSession || this.fridaSession.status !== frida_session_1.SessionStatus.ATTACHED) {
            return;
        }
        if (this.lastEmittedIndex < this.syscallEvents.length) {
            ws.getWss().clients.forEach((client) => __awaiter(this, void 0, void 0, function* () {
                client.send(JSON.stringify(this.syscallEvents.slice(this.lastEmittedIndex, this.syscallEvents.length)));
            }));
            this.lastEmittedIndex = this.syscallEvents.length;
        }
    }
}
exports.DapServer = DapServer;
//# sourceMappingURL=server.js.map