export interface ItemProps {
  clear(): void;
  activate(i: number): void;
  active: boolean;
  value: any;
  index: number;
  byteString: string;
}

export interface SetProps {
  activateSet(i: number): void;
  clearSet(): void;
  activateItem(i: number): void;
  clearItem(): void;
  set: number[];
  activeItem: number;
  index: number;
  active: boolean;
}

export interface RowProps {
  sets: number[][];
  heading: string;
}

export interface RowState {
  activeItem: number;
  activeSet: number;
}

export interface HexProps {
  rows: number[][][];
  bytesper: number;
}

export interface HexViewerProps {
  setLength: number;
  rowLength: number;
  buffer: number[];
}
