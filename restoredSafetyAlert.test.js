import test from "node:test";
import assert from "node:assert/strict";
import {
	restoreSafetyAtStartup,
	sendPermanentPromotionFailureAlert,
	sendRestoredSafetyAlert,
	sendSafetyActivationAlert,
} from "./restoredSafetyAlert.js";

function createManualTimer() {
	let scheduled;
	return {
		setTimeoutImpl(callback, delay) {
			assert.equal(scheduled, undefined, "only one deadline should be scheduled");
			scheduled = { callback, delay };
			return scheduled;
		},
		clearTimeoutImpl(handle) {
			if (scheduled === handle) scheduled = undefined;
		},
		advanceTo(delay) {
			assert.ok(scheduled, "expected an alert deadline to be scheduled");
			assert.equal(scheduled.delay, delay);
			const { callback } = scheduled;
			scheduled = undefined;
			callback();
		},
	};
}

test("sends only the active restored protection names", async () => {
	let request;
	const result = await sendRestoredSafetyAlert({
		state: { maintenance: true, emergencyLockdown: false, user: { password: "secret" } },
		destination: "https://alerts.example.test/private",
		fetchImpl: async (url, options) => {
			request = { url, options };
			return { ok: true, status: 204 };
		},
	});

	assert.deepEqual(result, { sent: true });
	assert.equal(request.url, "https://alerts.example.test/private");
	assert.deepEqual(JSON.parse(request.options.body), {
		content: "[SAFETY] Restored maintenance mode; server access remains restricted.",
	});
	assert.doesNotMatch(request.options.body, /secret|password|user/i);
});

test("does not deliver an alert when no protection is active", async () => {
	let called = false;
	const result = await sendRestoredSafetyAlert({
		state: {},
		destination: "https://alerts.example.test/private",
		fetchImpl: async () => {
			called = true;
		},
	});

	assert.deepEqual(result, { sent: false, reason: "not-configured" });
	assert.equal(called, false);
});

test("delivery failures are contained without exposing the destination", async () => {
	const originalError = console.error;
	const messages = [];
	console.error = message => messages.push(message);
	try {
		const result = await sendRestoredSafetyAlert({
			state: { emergencyLockdown: true },
			destination: "https://user:credential@alerts.example.test/private-token",
			fetchImpl: async () => {
				throw new Error("network unavailable");
			},
		});

		assert.deepEqual(result, { sent: false, reason: "delivery-failed" });
		assert.equal(messages.length, 1);
		assert.match(messages[0], /request failed/);
		assert.doesNotMatch(messages[0], /credential|private-token/);
	} finally {
		console.error = originalError;
	}
});

test("sends a private alert when protection is enabled during a live session", async () => {
	let request;
	const result = await sendSafetyActivationAlert({
		mode: "Emergency lockdown",
		destination: "https://alerts.example.test/private",
		fetchImpl: async (url, options) => {
			request = { url, options };
			return { ok: true, status: 204 };
		},
	});

	assert.deepEqual(result, { sent: true });
	assert.equal(request.url, "https://alerts.example.test/private");
	assert.deepEqual(JSON.parse(request.options.body), {
		content: "[SAFETY] Emergency lockdown enabled during a live session; server access is now restricted.",
	});
});

test("promotion alerts use their supplied destination without changing restored-safety routing", async () => {
	const requests = [];
	const fetchImpl = async (url) => {
		requests.push(url);
		return { ok: true, status: 204 };
	};

	await sendRestoredSafetyAlert({
		state: { maintenance: true },
		destination: "https://alerts.example.test/restored-safety",
		fetchImpl,
	});
	await sendPermanentPromotionFailureAlert({
		failureCount: 3,
		threshold: 3,
		windowMs: 300_000,
		destination: "https://alerts.example.test/permanent-promotion",
		fetchImpl,
	});

	assert.deepEqual(requests, [
		"https://alerts.example.test/restored-safety",
		"https://alerts.example.test/permanent-promotion",
	]);
});

test("promotion alerts safely skip delivery without a configured destination", async () => {
	let called = false;
	const result = await sendPermanentPromotionFailureAlert({
		failureCount: 3,
		threshold: 3,
		windowMs: 300_000,
		destination: null,
		fetchImpl: async () => {
			called = true;
		},
	});

	assert.deepEqual(result, { sent: false, reason: "not-configured" });
	assert.equal(called, false);
});

test("live activation alert delivery failure is contained", async () => {
	const originalError = console.error;
	console.error = () => {};
	try {
		const result = await sendSafetyActivationAlert({
			mode: "Maintenance mode",
			destination: "https://alerts.example.test/private",
			fetchImpl: async () => {
				throw new Error("network unavailable");
			},
		});

		assert.deepEqual(result, { sent: false, reason: "delivery-failed" });
	} finally {
		console.error = originalError;
	}
});

test("live activation continues when a hanging alert client ignores the abort signal", async () => {
	let aborted = false;
	let callerContinued = false;
	const timeoutMs = 20;
	const timer = createManualTimer();
	let markAlertStarted;
	const alertStarted = new Promise(resolve => {
		markAlertStarted = resolve;
	});
	const originalError = console.error;
	console.error = () => {};

	try {
		const delivery = sendSafetyActivationAlert({
			mode: "Maintenance mode",
			destination: "https://alerts.example.test/hanging",
			timeoutMs,
			setTimeoutImpl: timer.setTimeoutImpl,
			clearTimeoutImpl: timer.clearTimeoutImpl,
			fetchImpl: async (_url, { signal }) => new Promise(() => {
				markAlertStarted();
				signal.addEventListener("abort", () => {
					aborted = true;
				}, { once: true });
			}),
		});
		await alertStarted;

		assert.equal(aborted, false);
		assert.equal(callerContinued, false);
		timer.advanceTo(timeoutMs);
		const result = await delivery;
		callerContinued = true;

		assert.deepEqual(result, { sent: false, reason: "delivery-failed" });
		assert.equal(aborted, true);
		assert.equal(callerContinued, true);
	} finally {
		console.error = originalError;
	}
});

test("startup continues when a hanging alert client ignores the abort signal", async () => {
	const protectedState = { maintenance: true, emergencyLockdown: true };
	let activeState = { maintenance: false, emergencyLockdown: false };
	let aborted = false;
	let startupCompleted = false;
	const timeoutMs = 20;
	const timer = createManualTimer();
	let markAlertStarted;
	const alertStarted = new Promise(resolve => {
		markAlertStarted = resolve;
	});
	const originalError = console.error;
	console.error = () => {};

	try {
		const startup = restoreSafetyAtStartup({
			loadState: async () => protectedState,
			applyState: state => {
				activeState = state;
			},
			destination: "https://alerts.example.test/hanging",
			timeoutMs,
			setTimeoutImpl: timer.setTimeoutImpl,
			clearTimeoutImpl: timer.clearTimeoutImpl,
			fetchImpl: async (_url, { signal }) => new Promise(() => {
				markAlertStarted();
				signal.addEventListener("abort", () => {
					aborted = true;
					assert.deepEqual(activeState, protectedState);
				}, { once: true });
			}),
		}).then(result => {
			startupCompleted = true;
			return result;
		});
		await alertStarted;

		assert.equal(aborted, false);
		assert.equal(startupCompleted, false);
		assert.deepEqual(activeState, protectedState);
		timer.advanceTo(timeoutMs);
		const result = await startup;

		assert.equal(aborted, true);
		assert.equal(startupCompleted, true);
		assert.deepEqual(result, protectedState);
		assert.deepEqual(activeState, protectedState);
	} finally {
		console.error = originalError;
	}
});