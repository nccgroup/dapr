import { Event } from "./event";

export interface Driver {
  driverName: string;
}

export interface DriverTableProps {
  selectedDriver: string;
  selectDriver(e: string): void;
  drivers: Driver[];
  addEvents(e: Event[]): void;
  url: string;
}
