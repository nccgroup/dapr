import { DupEvent, Event } from "./event";

export interface DupEventTableProps {
  selectedDupEventID: number;
  selectDupEvent(e: string): void;
  events: DupEvent[];
}

export interface EventTableProps {
  selectedEventID: number;
  selectedDriver: string;
  selectEvent(e: number): void;
  events: Event[];
}
