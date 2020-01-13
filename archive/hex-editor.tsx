import * as React from "react";
import {
  ItemProps,
  SetProps,
  RowProps,
  RowState,
  HexProps,
  HexViewerProps
} from "../types/hex-editor-props";

class Item extends React.Component<ItemProps, {}> {
  activate() {
    this.props.activate(this.props.index);
  }
  clear() {
    this.props.clear();
  }
  render() {
    var classes =
      (this.props.active ? "active" : "") +
      (this.props.value == -1 ? " none" : "");
    return (
      <li
        className={classes}
        onMouseOver={this.activate.bind(this)}
        onMouseLeave={this.clear.bind(this)}
      >
        {this.props.byteString}
      </li>
    );
  }
}

class Set extends React.Component<SetProps, {}> {
  activate() {
    this.props.activateSet(this.props.index);
  }
  clear() {
    this.props.clearSet();
  }
  render() {
    var items = this.props.set.map((b: number, i: number) => {
      var byteString = "";

      if (b != -1) {
        byteString = b.toString(16);

        if (byteString.length == 1) {
          byteString = "0" + byteString;
        }
      }

      var active = this.props.activeItem == i && this.props.active;
      return (
        <Item
          index={i}
          key={i}
          value={b}
          byteString={byteString}
          active={active}
          activate={this.props.activateItem}
          clear={this.props.clearItem}
        />
      );
    });

    return (
      <ul
        className={"setHex" + (this.props.active ? " active" : "")}
        onMouseOver={this.activate.bind(this)}
        onMouseLeave={this.clear.bind(this)}
      >
        {items}
      </ul>
    );
  }
}

class Row extends React.Component<RowProps, RowState> {
  constructor(props: RowProps) {
    super(props);
    this.state = {
      activeSet: -1,
      activeItem: -1
    };
  }
  setActiveSet(activeSet: number): void {
    if (this.props.sets[activeSet][this.state.activeItem] == -1) return;
    this.setState({ activeSet: activeSet });
  }
  clearActiveSet(): void {
    this.setState({ activeSet: -1 });
  }
  setActiveItem(activeItem: number): void {
    this.setState({ activeItem: activeItem });
  }
  clearActiveItem(): void {
    this.setState({ activeItem: -1 });
  }
  render(): any {
    var sets = this.props.sets.map((set: number[], i: number) => {
      var active = this.state.activeSet == i ? true : false;

      var props = {
        set: set,
        key: i,
        index: i,
        active: active,
        activeItem: this.state.activeItem,

        activateSet: this.setActiveSet.bind(this),
        clearSet: this.clearActiveSet.bind(this),
        activateItem: this.setActiveItem.bind(this),
        clearItem: this.clearActiveItem.bind(this)
      };

      return <Set {...props} />;
    });

    var ascii = this.props.sets.map((set: number[], setIndex: number) => {
      return set.map((b: number, itemIndex: number, theSet: number[]) => {
        var c = "·";
        if (b > 31 && b < 127) {
          c = String.fromCharCode(b);
        }

        if (b == -1) {
          c = "";
        }

        var activeCell =
          this.state.activeSet * theSet.length + this.state.activeItem;
        var currentCell = setIndex * theSet.length + itemIndex;
        var classes = activeCell == currentCell ? "active" : "";

        return (
          <li key={itemIndex} className={classes}>
            {c}
          </li>
        );
      });
    });

    return (
      <div className="row">
        <div className="heading">{this.props.heading}:</div>
        {sets}
        <div className="ascii">
          <ul className="setAscii">{ascii}</ul>
        </div>
      </div>
    );
  }
}

class Hex extends React.Component<HexProps, {}> {
  render() {
    var pad = "000000";

    var rows = this.props.rows.map((row: number[][], i: number) => {
      var heading = "" + i * this.props.bytesper;
      heading = pad.substring(0, pad.length - heading.length) + heading;
      return <Row key={i} sets={row} heading={heading} />;
    });

    return (
      <div className="hexviewer">
        <div className="hex">{rows}</div>
      </div>
    );
  }
}

export default class HexViewer extends React.Component<HexViewerProps, {}> {
  render() {
    if (!this.props.buffer) {
      return null;
    }

    const rowChunk = this.props.rowLength,
      setChunk = this.props.setLength;
    let row: any[] = [];
    const rows: any[] = [];
    let set: number[] = [];
    let sets: any[] = [];

    const buffer = this.props.buffer;
    const bytes = this.props.buffer.length;

    for (var i = 0; i < bytes; i += rowChunk) {
      sets = [];
      let temparray: number[] = buffer.slice(i, i + rowChunk);

      for (let z = temparray.length; z < rowChunk; z++) {
        temparray.push(-1);
      }
      row = [];
      let x: number = 0;
      let k: number = temparray.length;
      for (; x < k; x += setChunk) {
        set = temparray.slice(x, x + setChunk);

        for (let z = set.length; z < setChunk; z++) {
          set.push(-1);
        }
        row.push(set);
      }
      rows.push(row);
    }

    return <Hex rows={rows} bytesper={rowChunk} />;
  }
}
