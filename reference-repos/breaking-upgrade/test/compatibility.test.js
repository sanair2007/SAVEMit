import assert from "node:assert/strict";
import test from "node:test";

import { supportedAxiosMajorVersion } from "../src/compatibility.js";

test("the application currently requires Axios 0.x compatibility", () => {
  assert.equal(supportedAxiosMajorVersion(), "0");
});
