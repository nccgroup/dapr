import * as _ from 'lodash';
import { Buffer } from 'buffer/';
import { Int64LE, Uint64LE } from 'int64-buffer';
import { Expression } from './expression';

export const BITS_PER_BYTE = 8;

let architecture: number = 0;

export enum Types {
  UNDEFINED,
  INT,
  CHAR,
  VOID,
  CUSTOM,
}

export class Struct {
  public def: StructDef;
  public fields: Field[];
  public data: Buffer;

  constructor(def: StructDef, data: Buffer) {
    this.def = def;
    this.data = data;
    this.fields = [];
    this.parse();
  }
  private parse(): void {
    let i = 0;
    this.def.fields.forEach(fieldDef => {
      try {
        const field: Field = new Field(fieldDef, this.data, i, this);
        this.fields.push(field);
        i += field.length;
      } catch (error) {
        console.error('Failed to parse field', error);
        console.error(JSON.stringify(fieldDef));
      }
    });
  }
}

export class Field {
  public def: FieldDef;
  public struct: Struct;
  public data: Buffer;
  public length: number;
  public name: string;
  public value: any;
  public output: string;

  constructor(def: FieldDef, data: Buffer, index: number, struct: Struct) {
    this.def = def;
    this.struct = struct;
    this.name = def.name;
    this.data = data;
    this.parse(index);
  }

  private parse(i: number): void {
    if (this.def.isPointer) {
      switch (architecture) {
        case 32:
          this.value = this.data.readUInt32LE(i);
          break;
        case 64:
          this.value = new Uint64LE(this.data.slice(i, i+8));
          break;
        default:
          throw new Error('invalid architecture');
      }
      this.length = this.def.width / BITS_PER_BYTE;
      this.output = this.value.toString(16);
    } else if (this.def.isArray) {
      this.length = this.def.lengthExpression.eval(this.struct) * (this.def.width / BITS_PER_BYTE);
      this.value = this.data.slice(i, i + this.length);
      if (this.def.type === Types.CHAR) {
        this.output = this.value.toString('ascii');
      } else {
        this.output = JSON.stringify(this.value);
      }
    } else if (this.def.type === Types.INT) {
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
            this.value = new Int64LE(this.data.slice(i, i+8));
            break;
          default:
            throw new Error('Invalid width');
        }
      } else {
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
            this.value = new Uint64LE(this.data.slice(i, i+8));
            break;
          default:
            throw new Error('Invalid width');
        }
      }
      this.output = this.value.toString();
      this.length = this.def.width / BITS_PER_BYTE;
    } else if (this.def.type === Types.CHAR) {
      this.value = this.data.readInt8(i);
      this.output = String.fromCharCode(this.value);
      this.length = 1;
    }
  }
}

export class FieldDef {
  private text: string;
  public name: string;
  public type: Types = Types.UNDEFINED;
  public width: number = 0;
  public lengthExpression: Expression = null;
  public isArray: boolean = false;
  public isSigned: boolean = false;
  public isPointer: boolean = false;
  public isEventLength: boolean = false;
  public isNullTerminatedString: boolean = false;
  constructor(text) {
    this.text = text;
    this.parse();
  }
  private parse() {
    const tokens = this.text.split(' ');
    this.name = tokens.pop();
    let match;
    tokens.forEach((token) => {
      if (!!(match = token.match(/^[ui](8|16|32|64)$/))) {
        this.type = Types.INT;
        this.isSigned = token[0] !== 'u';
        this.width = parseInt(match[1], 10);
      } else if (!!(match = token.match(/^u?char$/))) {
        this.type = Types.CHAR;
        this.isSigned = token[0] !== 'u';
        this.width = BITS_PER_BYTE;
      } else if (!!(match = token.match(/^void$/))) {
        this.type = Types.VOID;
        this.isSigned = false;
        this.width = architecture;
      } else if (!!(match = token.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/))) {
        this.type = Types.CUSTOM;
      } else if (!!(match = token.match(/^\[([^\[\]]+)\]$/))) {
        this.isArray = true;
        const insideArray = match[1];
        this.lengthExpression = new Expression(insideArray);
      } else if (token === '*') {
        this.width = architecture;
        this.isPointer = true;
      } else if (token === '~') {
        this.isEventLength = true;
      } else if (token === '@') {
        this.isNullTerminatedString = true;
      } else {
        throw new Error('Invalid type');
      }
    });

    // Validate field
    // TODO: Better validation
    //    e.g. throw an error on mutually exclusive type attributes
    if (this.type === Types.UNDEFINED) {
      throw new Error('Must set field type');
    } else if (this.type === Types.VOID && !this.isPointer) {
      throw new Error('Void type must be a pointer');
    } else if (this.isNullTerminatedString) {
      if (!this.isPointer || this.type !== Types.CHAR) {
        throw new Error('Null terminated string must be a char pointer');
      }
    }
  }
}

export class StructDef {
  public text: string;
  public name: string;
  public fields: FieldDef[];
  constructor(text: string) {
    this.fields = [];
    this.text = text;
    this.parse();
  }
  public parse() {
    if (!architecture) {
      throw new Error('Must set architecture');
    }
    this.text.trim().split('\n').forEach(line => {
      if (!line || line.length === 0) {
        return;
      }
      const tokens = line.trim().split(' ');
      if (tokens.length < 2) {
        throw new Error(
          `Invalid field definition: ${tokens.length} tokens in ${line}`
        );
      }
      if (tokens[0] === 'struct') {
        this.name = tokens[1];
      } else {
        if (!this.name) {
          throw new Error('Field definitions not in struct');
        }
        const field: FieldDef = new FieldDef(tokens);
        this.fields.push(field);
      }
    });
  }
}

export const arch = arch => {
  if (arch !== 32 && arch !== 64) {
    throw new Error('Architecture must be 32 or 64 bit');
  }
  architecture = arch;
};
