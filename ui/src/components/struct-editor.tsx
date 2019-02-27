import * as React from "react";
import * as _ from "lodash";
import { store } from "../index";
import { arch, StructDef } from "../types/struct-def";
import { editorSelectType, saveType } from "../actions/actions";
import { TypeEditorProps } from "../types/type-editor-props";

export default class StructEditor extends React.Component<TypeEditorProps, {}> {
  private typeText;
  private structDropdown;

  constructor(props) {
    super(props);
    this.structDropdown = React.createRef();
    this.typeText = React.createRef();
    arch(64);
  }
  private getSelectedTypeText(): string {
    console.log(JSON.stringify(this.props.selectedTypeForEditor));
    if (this.props.selectedTypeForEditor) {
      return this.props.selectedTypeForEditor.text;
    } else {
      return "";
    }
  }
  onChange(e) {
    const dropdown = this.structDropdown.current;
    const typeName = dropdown.options[dropdown.selectedIndex].value;
    store.dispatch(editorSelectType(typeName));
  }
  componentDidMount() {
    this.structDropdown.current[0] = new Option("<none>", "<none>");
  }
  componentDidUpdate() {
    this.typeText.current.value = this.getSelectedTypeText();
  }
  saveType(e) {
    const typeText = this.typeText.current.value;
    let type: StructDef;
    try {
      type = new StructDef(typeText);
      store.dispatch(saveType(type));
    } catch (e) {
      console.log("parse error", e);
    } finally {
      console.log(typeText);
      console.log(JSON.stringify(type));
    }
  }
  public render() {
    return (
      <div className="struct-editor-box">
        <select ref={this.structDropdown} onChange={this.onChange.bind(this)}>
          {_.map(this.props.types, type => {
            return <option key={type.name}>{type.name}</option>;
          })}
        </select>
        <br />
        <input type="button" value="save" onClick={this.saveType.bind(this)} />
        <br />
        <textarea ref={this.typeText} />
      </div>
    );
  }
}
