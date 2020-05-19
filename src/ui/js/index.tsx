import * as React from "react";
import * as ReactDOM from "react-dom";
import { createStore } from "redux";
import { Provider } from "react-redux";
import "./styles/index.css";
import App from "./containers/App";
import { rootReducer } from "./reducers/root-reducer";

export const store = createStore(rootReducer);

ReactDOM.render(
  <Provider store={store}>
    <App />
  </Provider>,
  document.getElementById("root")
);
