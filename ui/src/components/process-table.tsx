import * as React from "react";
import { ProcessTableProps } from "../types/process-table";
import ReactTable from "react-table";

export default (props: ProcessTableProps): React.ReactElement => {
  const [procs, setProcs] = React.useState([]);
  const columns = [
    { Header: "process ID", accessor: "pid" },
    { Header: "process name", accessor: "name" }
  ];
  const fetchCurrentProcesses = async (): Promise<void> => {
    const api: string = "procs";
    const respJSON = await fetch(`http://localhost:8888/${api}`);
    const resp = await respJSON.json();
    setProcs(resp);
  };

  const attachProcess = async (pid: string): Promise<void> => {
    const api = "session/attach";
    const respJSON = await fetch(`http://localhost:8888/${api}`, {
      method: "POST",
      body: JSON.stringify({ target: pid, adb: false })
    });
    const resp = await respJSON;
    console.log("HERE", resp);
  };
  React.useEffect(
    () => {
      fetchCurrentProcesses();
    },
    [props]
  );
  return <div />;
  /*    return (
        <ReactTable
            columns={columns}
            data={procs}
            getTrProps={(state: any, rowInfo: any, column: any, instance: any) => {
                if (rowInfo) {
                    let classname = "";
                    if (rowInfo.original.pid === props.selectedProcess) {
                        classname = "row-selected";
                    }

                    return {
                        onClick: (e: any, handleOriginal: any) => {
                            props.selectProcess(rowInfo.original.pid);
                            attachProcess(rowInfo.original.pid);
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
};
