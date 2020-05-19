/*  global Auth */

import * as React from "react";
import "../styles/App.css";
import {
  useTable,
  useBlockLayout,
  useResizeColumns,
  HeaderGroup,
  TableInstance,
  ColumnInstance
} from "react-table";

/*import * as thrift from "thrift/lib/nodejs/lib/thrift/browser";

   let host = window.location.hostname;
   let port = 80;
   let opts = {
   transport: thrift.TBufferedTransport,
   protocol: thrift.TJSONProtocol,
   headers: {
   "Content-Type": "application/vnd.apache.thrift.json"
   },
   https: false,
   path: "/hello",
   useCORS: true
   };
   console.log(Auth);

   let connection = thrift.createXHRConnection(host, port, opts);
   let thriftClient = thrift.createXHRClient(Auth.Client, connection);

   connection.on("error", err => console.error(err));

   const nameElement = document.getElementById("name_in") as HTMLInputElement;
   const outputElement = document.getElementById("output");
   document.getElementById("get_msg").addEventListener("click", async () => {
   const result = await thriftClient.get_message(nameElement.value);
   outputElement.innerHTML = result;
   });*/

/*import DriverTable from "../containers/driver-table";
   import ProcessTable from "../containers/process-table";
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
   <ProcessTable />
   <DriverTable />
   <DupEventTable />
   </div>
   );
   }

   return <EventDashboard />;
   }
   }



   const App: React.FC = props => {
   const [procs, setProcs] = React.useState([]);

   const fetchCurrentProcesses = async (): Promise<void> => {
   const api: string = "procs";
   const respJSON = await fetch(`http://localhost:8888/${api}`);
   const resp = await respJSON.json();
   setProcs(resp);
   };

   React.useEffect(
   () => {
   fetchCurrentProcesses();
   },
   [props]
   );
   interface Process {
   pid: number;
   name: string;
   cmd: string;
   ppid: number;
   uid: number;
   cpu: number;
   memory: number;
   }
   const procSelector = (
   <select>
   {_.map(procs, (value: Process) => (
   <option key={value.pid}>
   {value.pid} - {value.name}
   </option>
   ))}
   </select>
   );
   const columns = React.useMemo(
   () => [
   {
   Header: "ID",
   accessor: "id"
   },
   {
   Header: "Names",
   accessor: "name"
   }
   ],
   []
   );
   const data = React.useMemo(
   () => [{ id: 1, name: "jake" }, { id: 1, name: "jake" }],
   []
   );

   const table = useTable(
   {
   columns,
   data
   },
   useBlockLayout
   );

   return (
   <div {...table.getTableProps()} className="table">
   <div>
   {_.map(table.headerGroups, (headerGroup: HeaderGroup) => (
   <div {...headerGroup.getHeaderGroupProps()} className="tr">
   {_.map(headerGroup.headers, column => (
   <div {...column.getHeaderProps()} className="th">
   {column.render("Header")}
   </div>
   ))}
   </div>
   ))}
   </div>

   <div {...table.getTableBodyProps()}>
   {table.rows.map((row, i) => {
   table.prepareRow(row);
   return (
   <div {...row.getRowProps()} className="tr">
   {row.cells.map(cell => {
   return (
   <div {...cell.getCellProps()} className="td">
   {cell.render("Cell")}
   </div>
   );
   })}
   </div>
   );
   })}
   </div>
   </div>
   );
   };*/
//import { Event } from "../types/event";
import ProcessSelector from "./ProcessSelector";
import { EventsTable } from "../containers/event-table";

const App = () => {
  return (
    <div className="root">
      <div className="sidebar">
        <ul className="sidebarFeatures">
          <li>Proxy</li>
          <li>Repeater</li>
          <li>Structs</li>
        </ul>
        <ul className="sidebarPreferences">
          <li>Settings</li>
        </ul>
      </div>
      <div className="dataTable">
        <ProcessSelector clearTableData={() => console.log("clearing data")} />
        <textarea />
        <EventsTable />
      </div>
      <div className="detailsViews">
        <div className="hexViewer">hex viewer</div>
        <div className="structDetails">
          <div className="structViewer">struct viewer</div>
          <div className="structEditor">struct editor</div>
        </div>
      </div>
    </div>
  );
};

export default App;
