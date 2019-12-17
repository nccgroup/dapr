import React from "react";
import { Process } from "../types/process-table";
import * as _ from "lodash";

const ProcessSelector = () => {
  const [procs, setProcs] = React.useState([]);
  const [refresh, setRefresh] = React.useState(false);
  const fetchCurrentProcesses = async (): Promise<void> => {
    const api: string = "procs";
    const respJSON = await fetch(`http://localhost:8888/${api}`);
    const resp = await respJSON.json();
    setProcs(resp);
  };

  React.useEffect(
    () => {
      fetchCurrentProcesses();
    },
    [refresh]
  );

  return (
    <div>
      <button onClick={e => setRefresh(!refresh)}>Refresh</button>
      <select>
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
