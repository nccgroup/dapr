import { Field, StructDef } from "../types/struct-def";

export interface TypeDissectorProps {
  types: StructDef[];
  selectedTypeForDissector: StructDef;
  data: number[];
  fields: Field[];
  dissectorSelectType(t: string): void;
}
