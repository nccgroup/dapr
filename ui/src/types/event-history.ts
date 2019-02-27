import { Event } from "./event";

export interface EventHistoryProps {
  events: Event[];
  selectedEventID: number;
  selectHistoryEventID(i: number): void;
}
