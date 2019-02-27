import { connect } from "react-redux";
import { addEvent } from "../actions/actions";
import WebSocketComp from "../components/websocket";
import { Event } from "../types/event";
const mapStateToProps = (state: any) => ({
  url: state.url
});

const mapDispatchToProps = (dispatch: any) => ({
  addEvent: (e: Event) => dispatch(addEvent(e))
});

export default connect(mapStateToProps, mapDispatchToProps)(WebSocketComp);
