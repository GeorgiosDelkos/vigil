import { render } from "solid-js/web";

import { App } from "./App.tsx";
import "./style.css";
import "./settings.css";
import "./orbit.css";

const root = document.querySelector("#root");
if (root === null) {
  throw new Error("index.html has no #root element");
}
render(() => <App />, root);
