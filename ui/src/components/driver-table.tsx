import * as React from "react";
import { Event } from "../types/event";
import { DriverTableProps } from "../types/driver-table";
import ReactTable from "react-table";

const columns = [
  {
    Header: "driver",
    accessor: "driverName"
  }
];

export class DriverTable extends React.Component<DriverTableProps, {}> {
  public render(): any {
    let loading = false;
    if (this.props.drivers.length === 0) {
      fetch(`http://${this.props.url}/events`)
        .then((res: Response) => res.json())
        .then((res: Event[]) => this.props.addEvents(res));

      loading = true;
    }
    return <div />;
    /*    return (
      <ReactTable
        className={"full-page-height one-third-width"}
        data={this.props.drivers}
        columns={columns}
        loading={loading}
        getTrProps={(state: any, rowInfo: any, column: any, instance: any) => {
          if (rowInfo) {
            let classname = "";
            if (rowInfo.original.driverName === this.props.selectedDriver) {
              classname = "row-selected";
            }

            return {
              onClick: (e: any, handleOriginal: any) => {
                this.props.selectDriver(rowInfo.original.driverName);

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
    );*/
  }
}
