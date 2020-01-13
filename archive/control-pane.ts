import { connect } from "react-redux";
import ControlPane from "../components/control-pane";
import { back } from "../actions/actions";
const mapStateToProps = (state: any) => ({});

const mapDispatchToProps = (dispatch: any) => ({
  back: () => dispatch(back())
});

export default connect(mapStateToProps, mapDispatchToProps)(ControlPane);
