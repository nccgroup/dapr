import { Event } from "../types/event";

export interface WebSocketCompProps {
  addEvent(e: Event): void;
  url: string;
}
