import { connect } from "react-redux";
import StructEditor from "../components/struct-editor";
import {TypeEditorProps} from "../types/type-editor-props";
import { selectTypeByName } from "../utils/selectors";
import {State} from "../reducers/table-view";

const mapStateToProps = (state: State): TypeEditorProps => (
  {
    selectedTypeForEditor: selectTypeByName(state.selectedTypeForEditor, state.types),
    types: state.types
  });
const mapDispatchToProps = (state: any) => ({});

export default connect(mapStateToProps, mapDispatchToProps)(StructEditor);
