import * as React from "react";
import * as _ from "lodash";
import { install, uninstall, fetchCurrentProcesses } from "../utils/api";
interface Process {
  pid: number;
  name: string;
  cmd: string;
  ppid: number;
  uid: number;
  cpu: number;
  memory: number;
}

interface ProcessSelectorProps {
  clearTableData(): void;
}

const ProcessSelector = (props: ProcessSelectorProps) => {
  const [proc, setProc] = React.useState("");
  const [procs, setProcs] = React.useState([]);
  const [refresh, setRefresh] = React.useState(false);

  const onProcChange = async (
    e: React.FormEvent<HTMLSelectElement>
  ): Promise<void> => {
    const c = e.currentTarget.value;
    onDisconnect(e);
    setProc(c);
    const splits = _.split(c, " - ");
    const first = _.first(splits);
    if (!first) {
      return;
    }
    const procNum = _.parseInt(first);
    await install(procNum);
  };

  const onRefresh = async (
    _: React.MouseEvent<HTMLButtonElement>
  ): Promise<void> => setRefresh(!refresh);

  const onDisconnect = async (__: any): Promise<void> => {
    if (proc) {
      const procNum = _.first(_.split(proc, " - "));
      if (!procNum) {
        return;
      }
      await uninstall(procNum);
      props.clearTableData();
      setProc("");
    }
  };

  React.useEffect(
    () => {
      // Detach when the page loads so we know what state we are in
      const procNum = _.first(_.split(proc, " - "));
      if (!procNum) {
        return;
      }
      uninstall(procNum);
      fetchCurrentProcesses().then(procs => setProcs(procs));
    },
    [refresh]
  );

  return (
    <div>
      <button onClick={onRefresh}>Refresh</button>

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
