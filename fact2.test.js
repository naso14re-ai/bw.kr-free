import test from "node:test";
import assert from "node:assert/strict";
import facts from "../client/src/fact2.json" with { type: "json" };
import settings from "./settings.json" with { type: "json" };

test("fact2 has a public alias and a usable legacy-style fact collection", () => {
	assert.equal(settings.runlevel.fact2, 0);
	assert.ok(settings.publicCommands.includes("fact2"));
	assert.ok(settings.publicCommandAliases.includes("f2"));
	assert.ok(Array.isArray(facts));
	assert.ok(facts.length >= 20);
	for (const fact of facts) {
		assert.equal(typeof fact, "string");
		assert.ok(fact.trim().length > 0);
	}
});