import * as React from "react";
//import EventTable from "../containers/event-table";
import HexEditor from "../containers/hex-editor";
import StructEditor from "../containers/struct-editor";
import EventHistory from "../containers/event-history";
import StructDissection from "../containers/struct-dissection";
import ControlPane from "../containers/control-pane";

export default class EventDashboard extends React.Component<{}, {}> {
  public render(): any {
    return (
      <div className="dashboard-container">
        <ControlPane />
        <div className="dashboard">
          <div className="event-details">
            <HexEditor />
            <StructEditor />
            <EventHistory />
            <StructDissection />
          </div>
        </div>
      </div>
    );
  }
}
