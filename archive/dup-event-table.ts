import { connect } from "react-redux";
import { DupEventTable } from "../components/dup-event-table";
import * as _ from "lodash";
import { Event, DupEvent } from "../types/event";
import { selectDupEvent } from "../actions/actions";
import {
  selectEventsByDriverName,
  groupByDups,
  addDupLenKey
} from "../utils/selectors";

const mapStateToProps = (state: any) => ({
  events: addDupLenKey(
    groupByDups(selectEventsByDriverName(state.selectedDriver, state.events))
  ),
  selectedDupEventID: state.selectedDupEventID
});

const mapDispatchToProps = (dispatch: any) => ({
  selectDupEvent: (e: string) => dispatch(selectDupEvent(e))
});

export default connect(mapStateToProps, mapDispatchToProps)(DupEventTable);
