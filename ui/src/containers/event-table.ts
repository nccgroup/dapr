import { connect } from "react-redux";
import { EventsTable as EventsTableComp } from "../components/event-table";
import _ from "lodash";
import { selectEvent, addEvent } from "../actions/actions";
//import { selectCurrentGroupingWithID } from "../utils/selectors";

const mapStateToProps = (state: any) => {
  return {
    events: state.events,
    selectedDriver: state.selectedDriver,
    selectedEventID: state.selectedEventID
  };
};

const mapDispatchToProps = (dispatch: any) => ({
  selectEvent: (e: number) => dispatch(selectEvent(e)),
  addEvent: (e: SharedTypes.Syscall) => dispatch(addEvent(e))
});

export const EventsTable = connect(mapStateToProps, mapDispatchToProps)(
  EventsTableComp
);
