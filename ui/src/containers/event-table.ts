import { connect } from "react-redux";
import { EventTable } from "../components/event-table";
import * as _ from "lodash";
import { selectEvent } from "../actions/actions";
import { selectCurrentGroupingWithID } from "../utils/selectors";

const mapStateToProps = (state: any) => {
  return {
    events: selectCurrentGroupingWithID(
      state.events,
      state.selectedDriver,
      state.selectedDupEventKey
    ),
    selectedDriver: state.selectedDriver,
    selectedEventID: state.selectedEventID
  };
};

const mapDispatchToProps = (dispatch: any) => ({
  selectEvent: (e: number) => dispatch(selectEvent(e))
});

export default connect(mapStateToProps, mapDispatchToProps)(EventTable);
