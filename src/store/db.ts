import * as loki from "lokijs";

const db = new loki("dapr.database");
export const events = db.addCollection("events");
export const types = db.addCollection("types");
console.log("database", db);
