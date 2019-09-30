"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const int64_buffer_1 = require("int64-buffer");
const expression_1 = require("./expression");
exports.BITS_PER_BYTE = 8;
let architecture = 0;
var Types;
(function (Types) {
    Types[Types["UNDEFINED"] = 0] = "UNDEFINED";
    Types[Types["INT"] = 1] = "INT";
    Types[Types["CHAR"] = 2] = "CHAR";
    Types[Types["VOID"] = 3] = "VOID";
    Types[Types["CUSTOM"] = 4] = "CUSTOM";
})(Types = exports.Types || (exports.Types = {}));
class Struct {
    constructor(def, data) {
        this.def = def;
        this.data = data;
        this.fields = [];
        this.parse();
    }
    parse() {
        let i = 0;
        this.def.fields.forEach(fieldDef => {
            try {
                const field = new Field(fieldDef, this.data, i, this);
                this.fields.push(field);
                i += field.length;
            }
            catch (error) {
                console.error('Failed to parse field', error);
                console.error(JSON.stringify(fieldDef));
            }
        });
    }
}
exports.Struct = Struct;
class Field {
    constructor(def, data, index, struct) {
        this.def = def;
        this.struct = struct;
        this.name = def.name;
        this.data = data;
        this.parse(index);
    }
    parse(i) {
        if (this.def.isPointer) {
            switch (architecture) {
                case 32:
                    this.value = this.data.readUInt32LE(i);
                    break;
                case 64:
                    this.value = new int64_buffer_1.Uint64LE(this.data.slice(i, i + 8));
                    break;
                default:
                    throw new Error('invalid architecture');
            }
            this.length = this.def.width / exports.BITS_PER_BYTE;
            this.output = this.value.toString(16);
        }
        else if (this.def.isArray) {
            this.length = this.def.lengthExpression.eval(this.struct) * (this.def.width / exports.BITS_PER_BYTE);
            this.value = this.data.slice(i, i + this.length);
            if (this.def.type === Types.CHAR) {
                this.output = this.value.toString('ascii');
            }
            else {
                this.output = JSON.stringify(this.value);
            }
        }
        else if (this.def.type === Types.INT) {
            if (this.def.isSigned) {
                switch (this.def.width) {
                    case 8:
                        this.value = this.data.readInt8(i);
                        break;
                    case 16:
                        this.value = this.data.readInt16LE(i);
                        break;
                    case 32:
                        this.value = this.data.readInt32LE(i);
                        break;
                    case 64:
                        this.value = new int64_buffer_1.Int64LE(this.data.slice(i, i + 8));
                        break;
                    default:
                        throw new Error('Invalid width');
                }
            }
            else {
                switch (this.def.width) {
                    case 8:
                        this.value = this.data.readUInt8(i);
                        break;
                    case 16:
                        this.value = this.data.readUInt16LE(i);
                        break;
                    case 32:
                        this.value = this.data.readUInt32LE(i);
                        break;
                    case 64:
                        this.value = new int64_buffer_1.Uint64LE(this.data.slice(i, i + 8));
                        break;
                    default:
                        throw new Error('Invalid width');
                }
            }
            this.output = this.value.toString();
            this.length = this.def.width / exports.BITS_PER_BYTE;
        }
        else if (this.def.type === Types.CHAR) {
            this.value = this.data.readInt8(i);
            this.output = String.fromCharCode(this.value);
            this.length = 1;
        }
    }
}
exports.Field = Field;
class FieldDef {
    constructor(text) {
        this.type = Types.UNDEFINED;
        this.width = 0;
        this.lengthExpression = null;
        this.isArray = false;
        this.isSigned = false;
        this.isPointer = false;
        this.isEventLength = false;
        this.isNullTerminatedString = false;
        this.text = text;
        this.parse();
    }
    parse() {
        const tokens = this.text.split(' ');
        this.name = tokens.pop();
        let match;
        tokens.forEach((token) => {
            if (!!(match = token.match(/^[ui](8|16|32|64)$/))) {
                this.type = Types.INT;
                this.isSigned = token[0] !== 'u';
                this.width = parseInt(match[1], 10);
            }
            else if (!!(match = token.match(/^u?char$/))) {
                this.type = Types.CHAR;
                this.isSigned = token[0] !== 'u';
                this.width = exports.BITS_PER_BYTE;
            }
            else if (!!(match = token.match(/^void$/))) {
                this.type = Types.VOID;
                this.isSigned = false;
                this.width = architecture;
            }
            else if (!!(match = token.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/))) {
                this.type = Types.CUSTOM;
            }
            else if (!!(match = token.match(/^\[([^\[\]]+)\]$/))) {
                this.isArray = true;
                const insideArray = match[1];
                this.lengthExpression = new expression_1.Expression(insideArray);
            }
            else if (token === '*') {
                this.width = architecture;
                this.isPointer = true;
            }
            else if (token === '~') {
                this.isEventLength = true;
            }
            else if (token === '@') {
                this.isNullTerminatedString = true;
            }
            else {
                throw new Error('Invalid type');
            }
        });
        // Validate field
        // TODO: Better validation
        //    e.g. throw an error on mutually exclusive type attributes
        if (this.type === Types.UNDEFINED) {
            throw new Error('Must set field type');
        }
        else if (this.type === Types.VOID && !this.isPointer) {
            throw new Error('Void type must be a pointer');
        }
        else if (this.isNullTerminatedString) {
            if (!this.isPointer || this.type !== Types.CHAR) {
                throw new Error('Null terminated string must be a char pointer');
            }
        }
    }
}
exports.FieldDef = FieldDef;
class StructDef {
    constructor(text) {
        this.fields = [];
        this.text = text;
        this.parse();
    }
    parse() {
        if (!architecture) {
            throw new Error('Must set architecture');
        }
        this.text.trim().split('\n').forEach(line => {
            if (!line || line.length === 0) {
                return;
            }
            const tokens = line.trim().split(' ');
            if (tokens.length < 2) {
                throw new Error(`Invalid field definition: ${tokens.length} tokens in ${line}`);
            }
            if (tokens[0] === 'struct') {
                this.name = tokens[1];
            }
            else {
                if (!this.name) {
                    throw new Error('Field definitions not in struct');
                }
                const field = new FieldDef(tokens);
                this.fields.push(field);
            }
        });
    }
}
exports.StructDef = StructDef;
exports.arch = arch => {
    if (arch !== 32 && arch !== 64) {
        throw new Error('Architecture must be 32 or 64 bit');
    }
    architecture = arch;
};
//# sourceMappingURL=types.js.map