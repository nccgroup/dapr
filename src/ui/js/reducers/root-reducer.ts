import { eventsReducer } from "./events-reducer";
import { combineReducers } from "redux";

export const rootReducer = combineReducers({ eventsReducer });
export type RootState = ReturnType<typeof rootReducer>;
