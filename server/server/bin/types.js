"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const _ = require("lodash");
let architecture = null;
var Types;
(function (Types) {
    Types[Types["INT"] = 0] = "INT";
    Types[Types["CHAR"] = 1] = "CHAR";
    Types[Types["VOID"] = 2] = "VOID";
    Types[Types["CUSTOM"] = 3] = "CUSTOM";
})(Types = exports.Types || (exports.Types = {}));
class FieldDef {
    constructor(name = null, type = null, unsigned = false, pointer = false, arrayElements = 0) {
        this.name = name;
        this.type = type;
        this.unsigned = unsigned;
        this.pointer = pointer;
        this.arrayElements = arrayElements;
    }
}
exports.FieldDef = FieldDef;
class StructDef {
    constructor(name) {
        this.name = name;
        this.fields = [];
    }
}
exports.StructDef = StructDef;
exports.parse = (text) => {
    if (!architecture) {
        throw new Error('Must set architecture');
    }
    let struct = null;
    text.split('\n').forEach((line) => {
        if (!line || line.length === 0) {
            return;
        }
        const tokens = line.split(' ');
        if (tokens.length !== 2) {
            throw new Error('Invalid field definition');
        }
        if (tokens[0] === 'struct') {
            struct = new StructDef(tokens[1]);
        }
        else {
            if (!struct) {
                throw new Error('Field definitions not in struct');
            }
            const field = exports.parseField(tokens);
            struct.fields.push(field);
        }
    });
    return struct;
};
exports.parseField = (tokensArg) => {
    const tokens = _.isString(tokensArg) ? tokensArg.split(' ') : tokensArg;
    const field = new FieldDef();
    const type = tokens[0];
    field.name = tokens[1];
    let match;
    if (!!(match = type.match(/^[ui](8|16|32|64)/))) {
        field.type = Types.INT;
        field.unsigned = type[0] === 'u';
        field.width = parseInt(match[1], 10);
    }
    else if (!!(match = type.match(/^u?char/))) {
        field.type = Types.CHAR;
        field.unsigned = type[0] === 'u';
        field.width = 8;
    }
    else if (!!(match = type.match(/^void/))) {
        field.type = Types.VOID;
        field.unsigned = true;
        field.width = architecture;
    }
    else if (!!(match = type.match(/^[a-zA-Z0-9_\*\[\]]+$/))) {
        field.type = Types.CUSTOM;
    }
    else {
        throw Error('Invalid type');
    }
    if (!!(match = type.match(/\[([0-9]+)\]/))) {
        field.arrayElements = parseInt(match[1], 10);
    }
    if (!!(match = type.match(/\*/))) {
        field.pointer = true;
    }
    // Validate field
    if (field.type === Types.VOID && !field.pointer) {
        throw new Error('Void type must be pointer');
    }
    return field;
};
exports.arch = (arch) => {
    if (arch !== 32 && arch !== 64) {
        throw new Error('Architecture must be 32 or 64 bit');
    }
    architecture = arch;
};
//# sourceMappingURL=types.js.map