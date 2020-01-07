import * as React from "react";
import { map } from "lodash";
import { Syscall, SyscallType } from "../../../shared/types/syscalls";
import useWebSocket from "./useWebsocket";

export interface EventTableProps {
  selectedEventID: number;
  selectedDriver: string;
  selectEvent(e: number): void;
  addEvent(event: Syscall): void;
  events: Syscall[];
}
const columns: (keyof Syscall)[] = ["type", "syscall", "fd", "request"];

export const EventsTable = (props: EventTableProps) => {
  useWebSocket(`ws://localhost:8888`, {
    onMessage: (e: MessageEvent) => {
      const event: Syscall = Object.assign(
        {
          type: "",
          syscall: SyscallType.IOCTL,
          fd: 0,
          request: 0,
          data: new ArrayBuffer(0)
        },
        e.data
      );
      console.log("onmessage", event);
      props.addEvent(event);
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
