import * as React from "react";
import { uninstall } from "../utils/api";
import { useSelector, useDispatch } from "react-redux";
import { clearEvents } from "../actions/actions";
import * as _ from "lodash";

const DisconnectButton = () => {
  const onDisconnect = async (__: any): Promise<void> => {
    const proc = useSelector(state => state.currentlyAttachedProcess);
    const dispatch = useDispatch();
    if (proc) {
      await uninstall(_.first(_.split(proc, " - ")));
      dispatch(clearEvents());
    }
  };
  return <button onClick={onDisconnect}>Disconnect</button>;
};
