import * as express from "express";
/*
   # API Definition
   POST /session/detach

   # Description
   Detach from a Frida session.

   Note: The result of this operation can be checked by polling /session/status.
 */
export const sessionDetach = (
  _: express.Request,
  res: express.Response,
  __: express.NextFunction
) => {
  console.log(`detaching from ${this.fridaSession.session.pid}`);
  try {
    detach();
    res.send();
  } catch (e) {
    res.status(500).send(e.toString());
  }
};

const detach = (): void => {
  //TODO: fix this
  if (!!this.fridaSession) {
    this.fridaSession.detach();
  }
};
