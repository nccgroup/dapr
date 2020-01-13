import * as React from "react";
import ReactTable from "react-table";
import { EventHistoryProps } from "../types/event-history";
const columns = [
  {
    Header: "opcode",
    accessor: "opcode"
  },
  {
    Header: "timestamp",
    accessor: "start"
  },
  {
    Header: "mode",
    accessor: "mode"
  },
  {
    Header: "size",
    accessor: "size"
  },
  {
    Header: "request",
    accessor: "request"
  }
];
export default class EventHistory extends React.Component<
  EventHistoryProps,
  {}
> {
  public render(): any {
    let loading = false;
    if (this.props.selectedEventID === -1) {
      loading = true;
    }

    return <div />;
    /*    return (
      <ReactTable
        data={this.props.events}
        columns={columns}
        loading={loading}
        defaultSorted={[
          {
            id: "start",
            desc: true
          }
        ]}
        getTrProps={(state: any, rowInfo: any, column: any, instance: any) => {
          if (rowInfo) {
            let classname = "";
            if (rowInfo.original.id === this.props.selectedEventID) {
              classname = "row-selected";
            }

            return {
              onClick: (e: any, handleOriginal: any) => {
                this.props.selectHistoryEventID(rowInfo.original.id);

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
    );*/
  }
}
