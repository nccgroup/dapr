import * as React from "react";
import { map } from "lodash";
import useWebSocket from "./useWebsocket";

export interface EventTableProps {
  selectedEventID: number;
  selectedDriver: string;
  selectEvent(e: number): void;
  addEvent(event: SharedTypes.Syscall): void;
  events: SharedTypes.Syscall[];
}
const columns: (keyof SharedTypes.Syscall)[] = [
  "type",
  "syscall",
  "fd",
  "request"
];

export const EventsTable = (props: EventTableProps) => {
  useWebSocket(`ws://localhost:8888`, {
    onMessage: (e: SharedTypes.Syscall) => {
      console.log("onmessage", e);
      props.addEvent(e);
    },
    onClose: () => console.log("onclose"),
    onError: () => console.log("onerror")
  });

  return (
    <table>
      <thead>
        <tr>{map(columns, c => <th>{c}</th>)}</tr>
      </thead>
      <tbody>
        {map(props.events, e => (
          <tr>
            {map(columns, c => {
              <td>{e[c]}</td>;
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
};
