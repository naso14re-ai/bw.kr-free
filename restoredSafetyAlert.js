import { activeSafetyModeLabels } from "./ownerSafety.js";

const DELIVERY_TIMEOUT_MS = 5_000;

export async function restoreSafetyAtStartup({
	loadState,
	applyState,
	destination,
	fetchImpl = globalThis.fetch,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	setTimeoutImpl = globalThis.setTimeout,
	clearTimeoutImpl = globalThis.clearTimeout,
	onRestored,
} = {}) {
	const state = await loadState();
	applyState(state);
	if (activeSafetyModeLabels(state).length > 0) {
		onRestored?.(state);
		await sendRestoredSafetyAlert({
			state,
			destination,
			fetchImpl,
			timeoutMs,
			setTimeoutImpl,
			clearTimeoutImpl,
		});
	}
	return state;
}

export async function sendRestoredSafetyAlert({
	state,
	destination,
	fetchImpl = globalThis.fetch,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	setTimeoutImpl = globalThis.setTimeout,
	clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
	const modes = activeSafetyModeLabels(state);
	if (!destination || modes.length === 0) return { sent: false, reason: "not-configured" };

	return sendSafetyAlert({
		content: `[SAFETY] Restored ${modes.join(" and ")}; server access remains restricted.`,
		destination,
		fetchImpl,
		timeoutMs,
		setTimeoutImpl,
		clearTimeoutImpl,
		failureLabel: "Restored-protection",
	});
}

export async function sendSafetyActivationAlert({
	mode,
	destination,
	fetchImpl = globalThis.fetch,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	setTimeoutImpl = globalThis.setTimeout,
	clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
	if (!destination || !mode) return { sent: false, reason: "not-configured" };
	return sendSafetyAlert({
		content: `[SAFETY] ${mode} enabled during a live session; server access is now restricted.`,
		destination,
		fetchImpl,
		timeoutMs,
		setTimeoutImpl,
		clearTimeoutImpl,
		failureLabel: "Protection-activation",
	});
}

export async function sendPermanentPromotionFailureAlert({
	failureCount,
	threshold,
	windowMs,
	destination,
	fetchImpl = globalThis.fetch,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	setTimeoutImpl = globalThis.setTimeout,
	clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
	if (!destination) return { sent: false, reason: "not-configured" };
	return sendSafetyAlert({
		content: `[SAFETY] Permanent promotion storage failed ${Number(failureCount)} times within ${Number(windowMs)}ms (alert threshold: ${Number(threshold)}).`,
		destination,
		fetchImpl,
		timeoutMs,
		setTimeoutImpl,
		clearTimeoutImpl,
		failureLabel: "Permanent-promotion persistence",
	});
}

export function createSafetyActivationCommandHandlers({
	getState,
	setState,
	parseToggle,
	persistMode,
	recordAction,
	listUsers,
	destination,
	fetchImpl = globalThis.fetch,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	setTimeoutImpl = globalThis.setTimeout,
	clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
	async function activateMode(actor, {
		input,
		stateKey,
		persistenceKey,
		modeLabel,
		action,
		usage,
		saveFailure,
		notificationLabel,
		onEnabled,
	}) {
		const wasEnabled = getState()[stateKey];
		const next = parseToggle(input, wasEnabled);
		if (next === null) return actor.notify(usage);
		try {
			await persistMode(persistenceKey, next);
		} catch (error) {
			console.error(`persist ${notificationLabel.toLowerCase()}:`, error?.message || error);
			return actor.notify(saveFailure);
		}
		setState(stateKey, next);
		recordAction(actor, action, `${actor.public.name} turns ${notificationLabel.toLowerCase()} ${next ? "ON" : "OFF"}.`);
		onEnabled?.(next);
		actor.notify(`${notificationLabel} is now ${next ? "ON" : "OFF"}.`);
		if (next && !wasEnabled) {
			await sendSafetyActivationAlert({
				mode: modeLabel,
				destination,
				fetchImpl,
				timeoutMs,
				setTimeoutImpl,
				clearTimeoutImpl,
			});
		}
	}

	return {
		maintenancemode(input) {
			return activateMode(this, {
				input,
				stateKey: "maintenance",
				persistenceKey: "maintenance",
				modeLabel: "Maintenance mode",
				action: "maintenance",
				usage: "Usage: /maintenancemode [on|off|toggle]",
				saveFailure: "Maintenance mode was not changed because its safety state could not be saved.",
				notificationLabel: "Maintenance mode",
			});
		},
		emergencylockdown(input) {
			return activateMode(this, {
				input,
				stateKey: "emergencyLockdown",
				persistenceKey: "emergency_lockdown",
				modeLabel: "Emergency lockdown",
				action: "emergency_lockdown",
				usage: "Usage: /emergencylockdown [on|off|toggle]",
				saveFailure: "Emergency lockdown was not changed because its safety state could not be saved.",
				notificationLabel: "Emergency lockdown",
				onEnabled(next) {
					if (!next) return;
					for (const user of listUsers()) {
						if (user.runlevel < 8) {
							user.socket.emit("kick", { reason: "Emergency server lockdown" });
							user.disconnect();
						}
					}
				},
			});
		},
	};
}

async function sendSafetyAlert({
	content,
	destination,
	fetchImpl,
	timeoutMs,
	setTimeoutImpl,
	clearTimeoutImpl,
	failureLabel,
}) {
	const controller = new AbortController();
	let timeout;
	try {
		const request = Promise.resolve().then(() => fetchImpl(destination, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ content }),
				signal: controller.signal,
			}));
		const deadline = new Promise((_, reject) => {
			timeout = setTimeoutImpl(() => {
				controller.abort();
				reject(new DOMException("Alert delivery timed out", "AbortError"));
			}, timeoutMs);
		});
		const response = await Promise.race([request, deadline]);
		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		return { sent: true };
	} catch (error) {
		const reason = error?.name === "AbortError" ? "timed out" : "request failed";
		console.error(`[SAFETY] ${failureLabel} alert delivery failed (${reason}).`);
		return { sent: false, reason: "delivery-failed" };
	} finally {
		clearTimeoutImpl(timeout);
	}
}