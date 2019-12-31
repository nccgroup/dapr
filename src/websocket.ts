import * as ws from "ws";

let websocket: ws = null;
export const setWebsocket = (ws: ws) => {
  websocket = ws;
  return websocket;
};
export const getWebsocket = (): ws | null => websocket;
