import assert from "node:assert/strict";
import test from "node:test";

import { getCustomerProfile } from "../src/api-client.js";

test("customer API client is available", () => {
  assert.equal(typeof getCustomerProfile, "function");
});
