import * as React from "react";
import { TypeDissectorProps } from "../types/type-dissector-props";
import * as _ from "lodash";
import ReactTable from "react-table";

const columns = [
  {
    Header: "Name",
    accessor: "name"
  },
  {
    Header: "Value",
    accessor: "output"
  }
];

export default class StructDissection extends React.Component<
  TypeDissectorProps,
  {}
> {
  onChange(e) {
    // Whenever the value is changed, call the mapDispatchtoprops
    // function  that was passed from the container.
    this.props.dissectorSelectType(e.value);
  }
  public render() {
    return (
      <div className="struct-dissection-box">
        <select
          className="struct-dissection-selectbox"
          onChange={this.onChange}
        >
          {_.map(this.props.types, type => {
            return <option key={type.name}>{type.name}</option>;
          })}
        </select>
        <ReactTable
          className="struct-dissection-table"
          columns={columns}
          data={this.props.fields}
        />
      </div>
    );
  }
}
