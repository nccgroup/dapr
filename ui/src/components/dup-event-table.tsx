import * as React from "react";
import ReactTable from "react-table";
import { DupEventTableProps } from "../types/event-table";
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
  },
  {
    Header: "count",
    accessor: "count"
  }
];

export class DupEventTable extends React.Component<DupEventTableProps, {}> {
  public render(): any {
    let loading = false;
    if (this.props.events.length === 0) {
      loading = true;
    }
    return (
      <ReactTable
        data={this.props.events}
        columns={columns}
        loading={loading}
        className={"full-page-height two-thirds-width"}
        getTrProps={(state: any, rowInfo: any, column: any, instance: any) => {
          if (rowInfo) {
            let classname = "";
            if (rowInfo.original.id === this.props.selectedDupEventID) {
              classname = "row-selected";
            }

            return {
              onClick: (e: any, handleOriginal: any) => {
                this.props.selectDupEvent(rowInfo.original.key);

                // IMPORTANT! React-Table uses onClick internally to trigger
                // events like expanding SubComponents and pivots.
                // By default a custom 'onClick' handler will override this functionality.
                // If you want to fire the original onClick handler, call the
                // 'handleOriginal' function.
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
    );
  }
}
