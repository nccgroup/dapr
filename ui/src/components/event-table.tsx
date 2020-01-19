import * as React from "react";
import { map } from "lodash";
import useWebSocket from "./useWebsocket";
import { Syscall } from "../sharetypes/syscalls";
export interface EventTableProps {
  selectedEventID: number;
  selectedDriver: string;
  selectEvent(e: number): void;
  addEvent(event: Syscall): void;
  events: Syscall[];
}
const columns: (keyof Syscall)[] = ["type", "syscall", "fd", "request"];
const tableColumns = map(columns, c => <th key={c}>{c}</th>);
export const EventsTable = (props: EventTableProps) => {
  useWebSocket(`ws://localhost:8888`, {
    onMessage: (e: Syscall) => {
      console.log("onmessage", e);
      props.addEvent(e);
    },
    onClose: () => console.log("onclose"),
    onError: () => console.log("onerror")
  });

  const rows = map(props.events, (e, i) => (
    <tr key={i}>{map(columns, c => <td key={c}>{e[c]}</td>)}</tr>
  ));
  console.log("rows", rows);
  return (
    <table>
      <thead>
        <tr>{tableColumns}</tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  );
};
