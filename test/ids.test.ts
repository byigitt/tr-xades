import { test } from "node:test";
import assert from "node:assert/strict";
import { makeId } from "../src/ids.ts";

test("makeId — {Role}-Id-{uuid} pattern", () => {
	const id = makeId("Signature");
	assert.match(id, /^Signature-Id-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	assert.notEqual(makeId("Signature"), id, "two calls must produce different IDs");
});
