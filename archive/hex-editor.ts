import { connect } from "react-redux";
import HexEditor from "../components/hex-editor";
import { State } from "../reducers/table-view";
import { selectCurrentGrouping } from "../utils/selectors";
import * as _ from "lodash";

const mapStateToProps = (state: State) => ({
  setLength: 4,
  rowLength: 16,
  buffer:
    state.selectedEventID === -1
      ? []
      : _.filter(
          selectCurrentGrouping(
            state.events,
            state.selectedDriver,
            state.selectedDupEventKey
          ),
          i => i.id === state.selectedEventID
        )[0].data
});
const mapDispatchToProps = (dispatch: any) => ({});

export default connect(mapStateToProps, mapDispatchToProps)(HexEditor);
