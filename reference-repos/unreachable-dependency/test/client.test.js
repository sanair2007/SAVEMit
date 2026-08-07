import assert from "node:assert/strict";
import test from "node:test";
import { clientAvailable } from "../src/client.js";

test("client is available", () => assert.equal(clientAvailable(), true));
