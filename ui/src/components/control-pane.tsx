import * as React from "react";
import { ControlPaneProps } from "../types/control-pane";

export default class ControlPane extends React.Component<ControlPaneProps, {}> {
  public render() {
    return (
      <nav className="control-plane">
        <button onClick={this.props.back}>Back</button>
        <button>Stream</button>
        <button>Refresh</button>
      </nav>
    );
  }
}
