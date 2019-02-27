import { connect } from "react-redux";
import { DriverTable } from "../components/driver-table";
import { Event } from "../types/event";
import { selectDriver, addEvents } from "../actions/actions";
import { selectDrivers } from "../utils/selectors";

const mapStateToProps = (state: any) => ({
  drivers: selectDrivers(state.events),
  selectedDriver: state.selectedDriver,
  url: state.url
});

const mapDispatchToProps = (dispatch: any) => ({
  selectDriver: (e: string) => dispatch(selectDriver(e)),
  addEvents: (e: Event[]) => dispatch(addEvents(e))
});

export default connect(mapStateToProps, mapDispatchToProps)(DriverTable);
