import * as ws from "ws";

let websocket: ws | null = null;
export const setWebSocket = (ws: ws) => {
  websocket = ws;
  return websocket;
};
export const getWebSocket = (): ws | null => websocket;
