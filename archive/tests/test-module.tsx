import * as React from "react";
import { store } from "../index";
import * as actions from "../actions/actions";
import * as _ from "lodash";
import { Event } from "../types/event";
const getRandomInt = (max: number) => {
  return Math.floor(Math.random() * Math.floor(max));
};

const randomEvent = (): Event => {
  return {
    id: Math.random(),
    driverName: Math.random()
      .toString(36)
      .replace(/[^a-z]+/g, "")
      .substr(0, 5),
    opcode: Math.random(),
    mode: Math.random()
      .toString(36)
      .replace(/[^a-z]+/g, "")
      .substr(0, 5),
    size: Math.random(),
    start: Math.random(),
    data: [1, 2, 3],
    request: getRandomInt(0x100000000)
  };
};

const addRandomEvents = () => {
  const j = getRandomInt(100);
  let events: Event[] = [];
  for (let i = 0; i < j; i++) {
    events.push(randomEvent());
  }

  store.dispatch(actions.addEvents(events));
};
const addRandomEvent = () => {
  store.dispatch(actions.addEvent(randomEvent()));
};
const selectRandomDriver = () => {
  const drivers = _.map(store.getState().events, i => i.driverName);
  const randomDriver = _.sample(drivers) as string;
  console.log(drivers, randomDriver);
  store.dispatch(actions.selectDriver(randomDriver));
};

const selectRandomEvent = () => {};
export class TestModule extends React.Component {
  public render() {
    return (
      <div>
        <button onClick={addRandomEvent}>ADD RANDOM EVENT</button>
        <button onClick={addRandomEvents}>ADD RANDOM EVENTS</button>
        <button onClick={selectRandomDriver}>SELECT RANDOM DRIVER</button>
        <button onClick={selectRandomEvent}>SELECT RANDOM EVENT</button>
      </div>
    );
  }
}
