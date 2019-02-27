import { Event } from "../types/event";
import { ActionType } from "typesafe-actions";
import * as driverTableActions from "../actions/actions";
import * as _ from "lodash";
import { testEventData } from "../tests/test-data";
import { StructDef } from "../types/struct-def";

export type DriverTableAction = ActionType<typeof driverTableActions>;

export interface State {
  events: Event[];
  selectedDupEventKey: string;
  selectedEventID: number;
  selectedDriver: string;

  // type editor/dissector
  types: StructDef[];
  selectedTypeForDissector: string;
  selectedTypeForEditor: string;
  url: string;
}

const defaultState: State = {
  events: testEventData, //[],
  selectedDupEventKey: "",
  selectedEventID: -1,
  selectedDriver: "",
  types: [],
  selectedTypeForDissector: "",
  selectedTypeForEditor: "",
  url: "localhost:8888"
};

// State machine for the first view. Users can do one of the following actions:
// 1. click a row in the driver table
// 2. click a row in the event table
// 3. add a new event to the total set of events
// 4. replace all events
export function tableView(state = defaultState, action: DriverTableAction) {
  switch (action.type) {
    case driverTableActions.ADD_EVENT:
      return Object.assign({}, state, {
        events: state.events.concat(action.payload)
      });
    case driverTableActions.ADD_EVENTS:
      return Object.assign({}, state, {
        events: state.events.concat(action.payload)
      });
    case driverTableActions.SELECT_DRIVER:
      return Object.assign({}, state, {
        selectedDriver: action.payload,
        selectedDupEventKey: ""
      });
    case driverTableActions.SELECT_DUP_EVENT:
      return Object.assign({}, state, { selectedDupEventKey: action.payload });
    case driverTableActions.SELECT_EVENT:
      return Object.assign({}, state, { selectedEventID: action.payload });
    case driverTableActions.SAVE_TYPE:
      if (!_.find(state.types, type => type.name === action.payload.name)) {
        return Object.assign({}, state, {
          types: state.types.concat(action.payload)
        });
      }
    case driverTableActions.DISSECTOR_SELECT_TYPE:
      return Object.assign({}, state, {
        selectedTypeForDissector: action.payload
      });
    case driverTableActions.EDITOR_SELECT_TYPE:
      return Object.assign({}, state, {
        selectedTypeForEditor: action.payload
      });
    case driverTableActions.BACK:
      return Object.assign({}, state, {
        selectedEventID: -1,
        selectedDupEventKey: ""
      });
    default:
      return state;
  }
}
