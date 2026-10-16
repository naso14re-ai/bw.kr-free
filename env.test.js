import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
	loadServerEnv,
	permanentPromotionAlertUrl,
	restoredSafetyAlertUrl,
} from "./env.js";

test("loadServerEnv ignores missing .env files", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bonzi-env-"));
	assert.doesNotThrow(() => loadServerEnv(dir));
});

test("loadServerEnv loads values from the target directory", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bonzi-env-"));
	fs.writeFileSync(path.join(dir, ".env"), "PORT=1234\nTEST_VALUE=hello\n");

	const previous = process.env.TEST_VALUE;
	try {
		loadServerEnv(dir);
		assert.equal(process.env.TEST_VALUE, "hello");
	} finally {
		if (previous === undefined) {
			delete process.env.TEST_VALUE;
		} else {
			process.env.TEST_VALUE = previous;
		}
	}
});

test("restoredSafetyAlertUrl accepts only configured HTTP destinations", () => {
	assert.equal(restoredSafetyAlertUrl({}), null);
	assert.equal(restoredSafetyAlertUrl({ RESTORED_SAFETY_ALERT_URL: "file:///tmp/alert" }), null);
	assert.equal(
		restoredSafetyAlertUrl({ RESTORED_SAFETY_ALERT_URL: " https://alerts.example.test/private " }),
		"https://alerts.example.test/private",
	);
});

test("alert destinations are configured and validated independently", () => {
	const env = {
		RESTORED_SAFETY_ALERT_URL: "https://alerts.example.test/restored-safety",
		PERMANENT_PROMOTION_ALERT_URL: "https://alerts.example.test/permanent-promotion",
	};

	assert.equal(
		restoredSafetyAlertUrl(env),
		"https://alerts.example.test/restored-safety",
	);
	assert.equal(
		permanentPromotionAlertUrl(env),
		"https://alerts.example.test/permanent-promotion",
	);
	assert.equal(
		permanentPromotionAlertUrl({
			...env,
			PERMANENT_PROMOTION_ALERT_URL: "file:///tmp/promotion-alert",
		}),
		null,
	);
	assert.equal(
		restoredSafetyAlertUrl({
			...env,
			PERMANENT_PROMOTION_ALERT_URL: "not a URL",
		}),
		"https://alerts.example.test/restored-safety",
	);
});
