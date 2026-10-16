export class WeightedFloodGuard {
	constructor({
		windowMs = 10_000,
		maxScore = 15,
		strikeWindowMs = 5 * 60_000,
		blockDurationsMs = [2_000, 10_000],
		banAfterStrikes = 3,
		banMs = 5 * 60_000,
	} = {}) {
		this.windowMs = windowMs;
		this.maxScore = maxScore;
		this.strikeWindowMs = strikeWindowMs;
		this.blockDurationsMs = blockDurationsMs;
		this.banAfterStrikes = banAfterStrikes;
		this.banMs = banMs;
		this.states = new Map();
	}

	check(key, weight = 1, now = Date.now()) {
		const normalizedKey = String(key || "");
		if (!normalizedKey) return { action: "allow" };

		const state = this.states.get(normalizedKey) || {
			events: [],
			strikes: [],
			blockedUntil: 0,
			lastSeen: now,
		};
		state.lastSeen = now;
		state.events = state.events.filter((event) => now - event.at < this.windowMs);
		state.strikes = state.strikes.filter((at) => now - at < this.strikeWindowMs);

		if (state.blockedUntil > now) {
			this.states.set(normalizedKey, state);
			return { action: "drop", retryAfterMs: state.blockedUntil - now, strike: state.strikes.length };
		}

		const score = state.events.reduce((sum, event) => sum + event.weight, 0);
		const safeWeight = Math.max(0, Math.min(10, Number(weight) || 0));
		if (score + safeWeight <= this.maxScore) {
			state.events.push({ at: now, weight: safeWeight });
			this.states.set(normalizedKey, state);
			return { action: "allow" };
		}

		state.strikes.push(now);
		state.events = [];
		const strike = state.strikes.length;
		if (strike >= this.banAfterStrikes) {
			this.states.delete(normalizedKey);
			return { action: "ban", banMs: this.banMs, strike };
		}

		const blockMs = this.blockDurationsMs[Math.min(strike - 1, this.blockDurationsMs.length - 1)] || 2_000;
		state.blockedUntil = now + blockMs;
		this.states.set(normalizedKey, state);
		return { action: "block", retryAfterMs: blockMs, strike };
	}

	prune(now = Date.now()) {
		const expiry = Math.max(this.windowMs, this.strikeWindowMs);
		for (const [key, state] of this.states) {
			if (now - state.lastSeen > expiry && state.blockedUntil <= now) {
				this.states.delete(key);
			}
		}
	}
}

export class CoordinatedFloodGuard {
	constructor({
		guardOptions = {},
		coordinate,
		onSharedAction = () => {},
		onSharedError = () => {},
		now = () => Date.now(),
		flushDelayMs = 25,
		setTimeoutImpl = setTimeout,
	} = {}) {
		if (typeof coordinate !== "function") {
			throw new TypeError("CoordinatedFloodGuard requires a coordinate function");
		}
		this.local = new WeightedFloodGuard(guardOptions);
		this.coordinate = coordinate;
		this.onSharedAction = onSharedAction;
		this.onSharedError = onSharedError;
		this.now = now;
		this.flushDelayMs = flushDelayMs;
		this.setTimeoutImpl = setTimeoutImpl;
		this.pending = new Map();
		this.sharedBlocks = new Map();
	}

	check(key, weight = 1, now = this.now()) {
		const normalizedKey = String(key || "");
		if (!normalizedKey) return { action: "allow" };
		const shared = this.sharedBlocks.get(normalizedKey);
		if (shared?.blockedUntil > now) {
			return {
				action: "drop",
				retryAfterMs: shared.blockedUntil - now,
				strike: shared.strike,
			};
		}
		if (shared) this.sharedBlocks.delete(normalizedKey);

		this.enqueue(normalizedKey, weight, now);
		const result = this.local.check(normalizedKey, weight, now);
		return result;
	}

	enqueue(key, weight, at) {
		const safeWeight = Math.max(0, Math.min(10, Number(weight) || 0));
		let pending = this.pending.get(key);
		if (!pending) {
			pending = { events: [], timer: null, flushing: null };
			this.pending.set(key, pending);
		}
		pending.events.push({ at, weight: safeWeight });
		if (!pending.timer && !pending.flushing) {
			pending.timer = this.setTimeoutImpl(() => {
				pending.timer = null;
				void this.flush(key).catch(() => {});
			}, this.flushDelayMs);
			pending.timer?.unref?.();
		}
	}

	async flush(key) {
		const pending = this.pending.get(key);
		if (!pending) return null;
		if (pending.flushing) return pending.flushing;
		const events = pending.events.splice(0);
		if (!events.length) return null;
		pending.flushing = (async () => {
			try {
				const result = await this.coordinate(key, events);
				if (result?.blockedUntil > this.now()) {
					this.sharedBlocks.set(key, result);
					this.onSharedAction(key, result);
				}
				return result;
			} catch (error) {
				// Shared coordination is additive: local protection remains authoritative
				// on this server while unavailable shared storage is reported and skipped.
				this.onSharedError(key, error);
				return null;
			} finally {
				pending.flushing = null;
				if (pending.events.length) {
					await this.flush(key);
				} else if (!pending.timer) {
					this.pending.delete(key);
				}
			}
		})();
		return pending.flushing;
	}

	prune(now = this.now()) {
		this.local.prune(now);
		for (const [key, state] of this.sharedBlocks) {
			if (state.blockedUntil <= now) this.sharedBlocks.delete(key);
		}
	}
}