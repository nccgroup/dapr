import React from "react";
import { Process } from "../types/process-table";
import _ from "lodash";

export const daprTokenName = "dapr";
const auth = async (): Promise<string | null> => {
  const password = prompt("What's the password");
  const tokenJSON: Response = await jsonFetch("http://localhost:8888/auth", {
    method: "POST",
    body: JSON.stringify({ password: password })
  });
  if (tokenJSON.status === 403) {
    return null;
  }
  const { token }: { token: string } = await tokenJSON.json();
  return token;
};

const getAuthToken = (): string => localStorage.getItem(daprTokenName);
const jsonFetch = async (url: RequestInfo, opts?: RequestInit) => {
  let copyOpts = Object.assign({}, opts);
  if (!copyOpts.headers) {
    copyOpts.headers = {};
  }
  copyOpts.headers["Content-Type"] = "application/json";
  return await fetch(url, copyOpts);
};
const authedFetch = async (
  url: RequestInfo,
  opts?: RequestInit
): Promise<Response> => {
  let token: string;
  while (!(token = getAuthToken())) {
    token = await auth();
    if (token == null) {
      continue;
    }
    localStorage.setItem(daprTokenName, token);
    break;
  }
  let copyOpts = Object.assign({}, opts);
  if (!copyOpts.headers) {
    copyOpts.headers = {};
  }
  copyOpts.headers[daprTokenName] = token;
  return await jsonFetch(url, copyOpts);
};

interface ProcessSelectorProps {
  clearTableData(): void;
}

const ProcessSelector = (props: ProcessSelectorProps) => {
  const [proc, setProc] = React.useState("");
  const [procs, setProcs] = React.useState([]);
  const [refresh, setRefresh] = React.useState(false);
  const fetchCurrentProcesses = async (): Promise<void> => {
    const respJSON = await authedFetch(`http://localhost:8888/procs`);
    const resp = await respJSON.json();
    setProcs(resp);
  };

  const uninstall = async (pid: string): Promise<Response> =>
    await authedFetch(`http://localhost:8888/session/uninstall`, {
      method: "POST",
      body: JSON.stringify({ pid: pid })
    });

  const install = async (pid: number): Promise<Response> =>
    await authedFetch(`http://localhost:8888/session/install`, {
      method: "POST",
      body: JSON.stringify({ pid: pid, adb: false })
    });

  const onProcChange = async (
    e: React.FormEvent<HTMLSelectElement>
  ): Promise<void> => {
    const c = e.currentTarget.value;
    onDisconnect(e);
    setProc(c);
    await install(_.parseInt(_.first(_.split(c, " - "))));
  };

  const onRefresh = async (
    _: React.MouseEvent<HTMLButtonElement>
  ): Promise<void> => setRefresh(!refresh);

  const onDisconnect = async (__: any): Promise<void> => {
    if (proc) {
      await uninstall(_.first(_.split(proc, " - ")));
      props.clearTableData();
      setProc("");
    }
  };

  React.useEffect(
    () => {
      // Detach when the page loads so we know what state we are in
      uninstall(_.first(_.split(proc, " - ")));
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
