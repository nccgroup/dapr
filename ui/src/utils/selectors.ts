import * as _ from "lodash";
import { Event, DupEvent } from "../types/event";
import { Driver } from "../types/driver-table";
import { StructDef } from "../types/struct-def";

// selectEventsByDriverName filters the provided events by the specified
// driverName field.
export const selectEventsByDriverName = (
  name: string,
  events: Event[]
): Event[] => {
  if (name === "") return [];
  return _.filter(events, i => i.driverName == name);
};

// enumerate gives an array an ID
export const enumerate = (s: any, i: number): any => {
  s.id = i;
  return s;
};

export const selectCurrentGroupingWithID = (
  events: Event[],
  driver: string,
  dupEventKey: string
): Event[] => {
  return _.map(selectCurrentGrouping(events, driver, dupEventKey), enumerate);
};

// groupingDupFunc is the key used to group duplicate
// events by.
export const groupingDupFunc = (i: Event) =>
  `${i.request}-${i.driverName}-${i.opcode}`;

// selectCurrentEvent return the event object associated with
// the currently selected event in the event dashboard event
// table.
export const selectCurrentEvent = (
  events: Event[],
  driver: string,
  dupEventKey: string
): Event => {
  const dups: DupEvent[] = addDupLenKey(
    groupByDups(selectEventsByDriverName(driver, events))
  );
  return _.filter(dups, (i: DupEvent) => i.key === dupEventKey)[0];
};

// selectCurrentGrouping returns the events grouped
// for the currently selected row in the dup-event-table.
export const selectCurrentGrouping = (
  events: Event[],
  driver: string,
  dupEventKey: string
): Event[] => {
  let grouping: Event[] = [];
  _.forIn(groupByDups(events), (v: Event[], k: string) => {
    if (k === dupEventKey) {
      grouping = v;
    }
  });
  return grouping;
};

// getDrivers returns the unique set of drivers in a set of events.
export const selectDrivers = (events: Event[]): Driver[] => {
  return _.uniqBy(
    _.map(events, (e: Event): Driver => ({ driverName: e.driverName })),
    i => i.driverName
  );
};

// groupByDups groups a set of events by the groupDupFunction.
export const groupByDups = (events: Event[]): _.Dictionary<Event[]> =>
  _.groupBy(events, groupingDupFunc);

// addDupLenKey takes a grouping and returns a set of events
// where the number of duplicates is added to the column of the
// group.
export const addDupLenKey = (grouping: _.Dictionary<Event[]>): DupEvent[] => {
  let transform: DupEvent[] = [];
  _.forIn(grouping, (v: Event[], k: string) => {
    const event: DupEvent = _.first(v) as DupEvent;
    if (event) {
      event.count = v.length;
      event.key = k;
      transform.push(event);
    }
  });

  return transform;
};

// selectTimportalID provided an event and a list of events, returns
// the ID of the event in the set of events after they have been sorted
// by start.
export const selectIDByTimestamp = (e: number, events: Event[]): number => {
  return _.filter(events, i => i.start === e)[0].id;
};
export const selectTypeByName = (
  typeName: string,
  types: StructDef[]
): StructDef => {
  return _.filter(types, i => i.name === typeName)[0];
};
