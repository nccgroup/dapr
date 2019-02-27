import * as React from "react";
import "../styles/App.css";
import DriverTable from "../containers/driver-table";
import DupEventTable from "../containers/dup-event-table";
import { AppProps } from "../types/app-props";
import EventDashboard from "../containers/event-dashboard";
import WebSocket from "../containers/websocket";
export default class App extends React.Component<AppProps, {}> {
  public render(): any {
    if (this.props.eventSelection) {
      return (
        <div className="dup-event-table-container">
          <WebSocket />
          <DriverTable />
          <DupEventTable />
        </div>
      );
    }

    return <EventDashboard />;
  }
}
