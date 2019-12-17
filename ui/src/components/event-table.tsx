import * as React from "react";
import ReactTable from "react-table";
import { EventTableProps } from "../types/event-table";
const columns = [
  {
    Header: "id",
    accessor: "id"
  }
];

export class EventTable extends React.Component<EventTableProps, {}> {
  public render(): any {
    let loading = false;
    if (this.props.events.length === 0) {
      loading = true;
    }
    return (
      <div className={"event-table-col"}>
        <h1>{this.props.selectedDriver}</h1>
      </div>
    );
  }
}
