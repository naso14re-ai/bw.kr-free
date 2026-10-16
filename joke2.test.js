import test from "node:test";
import assert from "node:assert/strict";
import jokes from "../client/src/joke2.json" with { type: "json" };

test("joke2 data contains enough non-empty joke parts", () => {
	assert.ok(Array.isArray(jokes), "joke2 data should be an array");
	assert.ok(jokes.length >= 10, "joke2 should contain at least ten joke parts");
	assert.equal(jokes.length % 2, 0, "joke2 should contain an even number of parts");
	for (const part of jokes) {
		assert.equal(typeof part, "string", "each joke part should be a string");
		assert.ok(part.trim().length > 0, "each joke part should not be empty");
	}
});
