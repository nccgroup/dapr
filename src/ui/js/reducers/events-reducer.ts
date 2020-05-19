import { ActionType } from "typesafe-actions";
import * as driverTableActions from "../actions/actions";
import * as _ from "lodash";
//import { testEventData } from "../tests/test-data";
import { Syscall } from "../../../shared/types/syscalls";
export type DriverTableAction = ActionType<typeof driverTableActions>;

export interface State {
  events: Syscall[];
  selectedEventID: number;
  currentlyAttachedProcess: string;
}

const defaultState: State = {
  events: [],
  selectedEventID: -1,
  currentlyAttachedProcess: ""
};

export const eventsReducer = (
  state = defaultState,
  action: DriverTableAction
) => {
  switch (action.type) {
    case driverTableActions.CLEAR_EVENTS:
      return Object.assign({}, state, { events: [] });
    case driverTableActions.SELECT_PROCESS:
      return Object.assign({}, state, {
        selectedProcess: action.payload,
        events: []
      });
    case driverTableActions.ADD_EVENT:
      return Object.assign({}, state, {
        events: state.events.concat(action.payload)
      });
    case driverTableActions.ADD_EVENTS:
      return Object.assign({}, state, {
        events: state.events.concat(action.payload)
      });
    /*
    case driverTableActions.SELECT_DRIVER:
      return Object.assign({}, state, {
        selectedDriver: action.payload,
        selectedDupEventKey: ""
      });
    case driverTableActions.SELECT_DUP_EVENT:
      return Object.assign({}, state, { selectedDupEventKey: action.payload });*/
    case driverTableActions.SELECT_EVENT:
      return Object.assign({}, state, { selectedEventID: action.payload });
    /*    case driverTableActions.SAVE_TYPE:
               if (!_.find(state.types, type => type.name === action.payload.name)) {
               return Object.assign({}, state, {
               types: state.types.concat(action.payload)
               });
               }*/
    /* case driverTableActions.DISSECTOR_SELECT_TYPE:
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
      });*/
    default:
      return state;
  }
};
