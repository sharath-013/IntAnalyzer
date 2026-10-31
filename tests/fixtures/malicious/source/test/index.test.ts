import { test } from "node:test";
import assert from "node:assert";
import { percent } from "../src/index";

test("percent", () => assert.equal(percent(1, 4), 25));
