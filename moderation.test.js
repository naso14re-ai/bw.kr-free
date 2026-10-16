import test from "node:test";
import assert from "node:assert/strict";
import {
	BAN_DURATIONS_MS,
	MUTE_DURATION_MS,
	moderationMinimumRunlevel,
	parseModerationRequest,
} from "./moderation.js";

test("ban durations are a fixed allowlist", () => {
	assert.deepEqual(Object.keys(BAN_DURATIONS_MS), [
		"5m", "10m", "15m", "30m", "45m", "1h", "2h", "3h", "6h", "permanent",
	]);
	assert.equal(BAN_DURATIONS_MS["45m"], 45 * 60_000);
	assert.equal(BAN_DURATIONS_MS.permanent, null);
	assert.equal(parseModerationRequest("ban 7m abc reason"), null);
});

test("mute is fixed to 15 minutes", () => {
	assert.equal(MUTE_DURATION_MS, 15 * 60_000);
	assert.deepEqual(parseModerationRequest("mute 15m abc flooding"), {
		action: "mute",
		duration: "15m",
		target: "abc",
		reason: "flooding",
	});
	assert.equal(parseModerationRequest("mute 30m abc flooding"), null);
});

test("moderation actions enforce their minimum ranks", () => {
	assert.equal(moderationMinimumRunlevel("kick"), 2);
	assert.equal(moderationMinimumRunlevel("ban", "5m"), 2);
	assert.equal(moderationMinimumRunlevel("ban", "permanent"), 3);
	assert.equal(moderationMinimumRunlevel("mute"), 3);
	assert.equal(moderationMinimumRunlevel("shadowban"), 4);
	assert.equal(moderationMinimumRunlevel("unshadowban"), 4);
});