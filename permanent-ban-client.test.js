import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const clientSource = readFileSync(
	new URL("../client/src/script.js", import.meta.url),
	"utf8",
);
const serverSource = readFileSync(new URL("./server.js", import.meta.url), "utf8");

test("permanent bans use the sanitized ban screen instead of a media redirect", () => {
	assert.doesNotMatch(clientSource, /socket\.on\("banned"/);
	assert.doesNotMatch(clientSource, /nyancat\.mp4/);
	assert.match(clientSource, /ban_reason\.textContent/);
	assert.match(clientSource, /Never \(permanent ban\)/);
	assert.doesNotMatch(serverSource, /socket\.emit\("banned"/);
	assert.match(serverSource, /bans\.get\(ip\)/);
});