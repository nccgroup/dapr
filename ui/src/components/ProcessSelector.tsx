import React from "react";
import { Process } from "../types/process-table";
import * as _ from "lodash";

interface ProcessSelectorProps {
  clearTableData(): void;
}

const ProcessSelector = (props: ProcessSelectorProps) => {
  const [proc, setProc] = React.useState("");
  const [procs, setProcs] = React.useState([]);
  const [refresh, setRefresh] = React.useState(false);
  const fetchCurrentProcesses = async (): Promise<void> => {
    const api: string = "procs";
    const key = "key";
    const apiKey = localStorage.getItem(key);

    try {
      const respJSON = await fetch(`http://localhost:8888/${api}`, {
        headers: { "X-DAPR-TOKEN": apiKey }
      });
      const resp = await respJSON.json();
      setProcs(resp);
    } catch (e) {
      console.error(e);
      return;
    }
  };

  const detach = async (): Promise<void> => {
    const api = "session/detach";
    const key = "key";
    const apiKey = localStorage.getItem(key);
    await fetch(`http://localhost:8888/${api}`, {
      method: "POST",
      headers: {
        "X-DAPR-TOKEN": apiKey
      }
    });
  };
  const attach = async (procID: number): Promise<void> => {
    const api = "session/attach";
    const body = { target: procID, adb: false };
    const key = "key";
    const apiKey = localStorage.getItem(key);

    await fetch(`http://localhost:8888/${api}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-DAPR-TOKEN": apiKey
      },
      body: JSON.stringify(body)
    });
  };

  const onProcChange = async (
    e: React.FormEvent<HTMLSelectElement>
  ): Promise<void> => {
    const c = e.currentTarget.value;
    onDisconnect(e);
    setProc(c);
    await attach(_.parseInt(_.first(_.split(c, " - "))));
  };

  const onRefresh = async (
    _: React.MouseEvent<HTMLButtonElement>
  ): Promise<void> => setRefresh(!refresh);

  const onDisconnect = async (_: any): Promise<void> => {
    if (proc) {
      await detach();
      props.clearTableData();
      setProc("");
    }
  };

  React.useEffect(
    () => {
      // Detach when the page loads so we know what state we are in
      detach();
      fetchCurrentProcesses();
    },
    [refresh]
  );

  return (
    <div>
      <button onClick={onRefresh}>Refresh</button>
      <button onClick={onDisconnect}>Disconnect</button>
      <select value={proc} onChange={onProcChange}>
        {_.map(procs, (value: Process) => (
          <option key={value.pid}>
            {value.pid} - {value.name}
          </option>
        ))}
      </select>
    </div>
  );
};
export default ProcessSelector;
