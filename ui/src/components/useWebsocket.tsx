import * as React from "react";
/*
   export default class WebSocketComp extends React.Component<
   WebSocketCompProps,
   {}
   > {
   public render() {
   return <span className="hidden" />;
   }
   public componentDidMount() {
   // When the application loads for the first time, connect to the websocket.
   this.connectWebsocket();
   }

   private connectWebsocket() {
   const websocket = new WebSocket(`ws://${this.props.url}/event-stream`);
   websocket.onopen = (): void => {
   console.log("websocket opened");
   };

   websocket.onmessage = (event: MessageEvent) => {
   try {
   const data: Event = JSON.parse(event.data);
   this.props.addEvent(data);
   } catch (e) {
   console.error(e);
   }
   };

   websocket.onclose = () => {
   console.log("websocket closed");
   //      setTimeout(this.connectWebsocket, 1500);
   };
   }
   }*/
import { Syscall } from "../sharetypes/syscalls";
interface WebSocketClientOptions {
  onMessage(e: Syscall): void;
  onClose(): void;
  onError(): void;
}
const useWebSocket = (url: string, options: WebSocketClientOptions) => {
  let websocket: WebSocket;
  const sendMessage = (message: string) => {
    if (websocket) {
      websocket.send(message);
    }
  };
  React.useEffect(() => {
    websocket = new WebSocket(url);
    websocket.onopen = (): void => {
      console.log("opened");
    };
    websocket.onmessage = (e: MessageEvent) => {
      const data: Syscall = JSON.parse(e.data);
      options.onMessage(data);
    };
    websocket.onclose = options.onClose;
    websocket.onerror = options.onError;
  }, []);

  return [sendMessage];
};
export default useWebSocket;
