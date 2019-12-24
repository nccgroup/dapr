import * as express from "express";
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
export const getTypes = (_: express.Request, resp: express.Response) => {
  this.fridaSession
    .typeGetAll()
    .then(result => resp.send(result))
    .catch(e => resp.status(500).send(e.toString()));
};
