import { connect } from "react-redux";
import ProcessTable from "../components/process-table";
import * as actions from "../actions/actions";
const mapStateToProps = (state: any) => ({
  selectedProcess: state.selectedProcess
});
const mapDispatchToProps = (dispatch: any) => ({
  selectProcess: (pid: string) => dispatch(actions.selectProcess(pid))
});

export default connect(mapStateToProps, mapDispatchToProps)(ProcessTable);
