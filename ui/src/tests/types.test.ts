import * as assert from "assert";
import { StructDef, FieldDef, arch, Types } from "../types/struct-def";

arch(64);
test("parses types correctly", () => {
  const structDef = new StructDef(`
struct foo
u32 a
i64[12] b
char c
char[32] buf
uchar* data
void* va
u8* framebuffer
`);
  expect(structDef.fields.length).toBe(7);
  expect(structDef.name).toBe("foo");

  expect(structDef.fields[0].name).toBe("a");
  expect(structDef.fields[0].type).toBe(Types.INT);
  expect(structDef.fields[0].width).toBe(32);
  expect(structDef.fields[0].unsigned).toBe(true);
  expect(structDef.fields[0].pointer).toBe(false);
  expect(structDef.fields[0].arrayElements).toBe(0);

  expect(structDef.fields[1].name).toBe("b");
  expect(structDef.fields[1].type).toBe(Types.INT);
  expect(structDef.fields[1].width).toBe(64);
  expect(structDef.fields[1].unsigned).toBe(false);
  expect(structDef.fields[1].pointer).toBe(false);
  expect(structDef.fields[1].arrayElements).toBe(12);

  expect(structDef.fields[2].name).toBe("c");
  expect(structDef.fields[2].type).toBe(Types.CHAR);
  expect(structDef.fields[4].width).toBe(8);
  expect(structDef.fields[2].unsigned).toBe(false);
  expect(structDef.fields[2].pointer).toBe(false);
  expect(structDef.fields[2].arrayElements).toBe(0);

  expect(structDef.fields[3].name).toBe("buf");
  expect(structDef.fields[3].type).toBe(Types.CHAR);
  expect(structDef.fields[4].width).toBe(8);
  expect(structDef.fields[3].unsigned).toBe(false);
  expect(structDef.fields[3].pointer).toBe(false);
  expect(structDef.fields[3].arrayElements).toBe(32);

  expect(structDef.fields[4].name).toBe("data");
  expect(structDef.fields[4].type).toBe(Types.CHAR);
  expect(structDef.fields[4].width).toBe(8);
  expect(structDef.fields[4].unsigned).toBe(true);
  expect(structDef.fields[4].pointer).toBe(true);
  expect(structDef.fields[4].arrayElements).toBe(0);

  expect(structDef.fields[5].name).toBe("va");
  expect(structDef.fields[5].type).toBe(Types.VOID);
  expect(structDef.fields[5].width).toBe(64);
  expect(structDef.fields[5].unsigned).toBe(true);
  expect(structDef.fields[5].pointer).toBe(true);
  expect(structDef.fields[5].arrayElements).toBe(0);

  expect(structDef.fields[6].name).toBe("framebuffer");
  expect(structDef.fields[6].type).toBe(Types.INT);
  expect(structDef.fields[4].width).toBe(8);
  expect(structDef.fields[6].unsigned).toBe(true);
  expect(structDef.fields[6].pointer).toBe(true);
  expect(structDef.fields[6].arrayElements).toBe(0);
});

test("should parse custom types directly", () => {
  let field: FieldDef = new FieldDef("CustomType[101] data");
  expect(field.name).toBe("data");
  expect(field.type).toBe(Types.CUSTOM);
  expect(field.arrayElements).toBe(101);
});
