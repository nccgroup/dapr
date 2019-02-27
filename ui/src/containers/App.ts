import { connect } from "react-redux";
import App from "../components/App";

const mapStateToProps = (state: any) => ({
  eventSelection: state.selectedDupEventKey === ""
});

const mapDispatchToProps = (state: any) => ({});

export default connect(mapStateToProps, mapDispatchToProps)(App);
