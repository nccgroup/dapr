import { StructDef } from "../types/struct-def";

export interface TypeEditorProps {
  types: StructDef[];
  selectedTypeForEditor: StructDef;
}
