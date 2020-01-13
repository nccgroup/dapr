import { DupEvent, Event } from "./event";

export interface DupEventTableProps {
  selectedDupEventID: number;
  selectDupEvent(e: string): void;
  events: DupEvent[];
}
