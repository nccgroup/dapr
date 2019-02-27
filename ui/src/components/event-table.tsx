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
        <ReactTable
          data={this.props.events}
          columns={columns}
          loading={loading}
          className={"event-table"}
          getTrProps={(
            state: any,
            rowInfo: any,
            column: any,
            instance: any
          ) => {
            if (rowInfo) {
              let classname = "";
              if (rowInfo.original.id === this.props.selectedEventID) {
                classname = "row-selected";
              }

              return {
                onClick: (e: any, handleOriginal: any) => {
                  this.props.selectEvent(rowInfo.original.id);

                  if (handleOriginal) {
                    handleOriginal();
                  }
                },
                className: classname
              };
            } else {
              return {};
            }
          }}
        />
      </div>
    );
  }
}
