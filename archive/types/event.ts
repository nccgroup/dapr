export interface Event {
  id: number;
  driverName: string;
  opcode: number;
  mode: string;
  size: number;
  start: number;
  data: number[];
  request: number;
}

export interface DupEvent extends Event {
  count: number;
  key: string;
}
