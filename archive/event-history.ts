import { connect } from "react-redux";
import EventHistory from "../components/event-history";
import { Event } from "../types/event";
import * as _ from "lodash";
import { selectHistoryEvent } from "../actions/actions";
import { State } from "../reducers/table-view";
import { selectCurrentGrouping, selectIDByTimestamp } from "../utils/selectors";

const mapStateToProps = (state: State) => ({
  events: state.events,
  selectedEventID:
    state.selectedEventID === -1
      ? -1
      : selectIDByTimestamp(
          _.filter(
            selectCurrentGrouping(
              state.events,
              state.selectedDriver,
              state.selectedDupEventKey
            ),
            i => i.id === state.selectedEventID
          )[0].start,
          state.events
        )
});

const mapDispatchToProps = (dispatch: any) => ({
  selectHistoryEventID: (i: number) => dispatch(selectHistoryEvent(i))
});

export default connect(mapStateToProps, mapDispatchToProps)(EventHistory);
