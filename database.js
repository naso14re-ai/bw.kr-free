import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir, readdir, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Storage } from "@google-cloud/storage";
import sqlite3 from "sqlite3";
import { sanitizeUnicode } from "./utils.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new sqlite3.Database(path.join(__dirname, "bonziworld.db"));
if (!process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID) {
	throw new Error(
		"DEFAULT_OBJECT_STORAGE_BUCKET_ID is required for shared outage-alert cooldown coordination",
	);
}
const REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";
const operationalStorageOptions = {
	credentials: {
		audience: "replit",
		subject_token_type: "access_token",
		token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
		type: "external_account",
		credential_source: {
			url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
			format: {
				type: "json",
				subject_token_field_name: "access_token",
			},
		},
		universe_domain: "googleapis.com",
	},
	projectId: "",
};
const operationalStorage = new Storage(operationalStorageOptions);
const operationalBucket = operationalStorage.bucket(
	process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID,
);
const PERMANENT_PROMOTION_ALERT_KEY = "permanent_promotion_persistence";
const COOLDOWN_COORDINATION_HEALTH_KEY = "cooldown_coordination_health";
const COOLDOWN_COORDINATION_STAGES = new Set(["load", "save", "cleanup"]);
const COOLDOWN_HEALTH_STORAGE_TIMEOUT_MS = 1_000;
const PROMOTION_COOLDOWN_STORAGE_TIMEOUT_MS = 1_000;

const ANTI_FLOOD_STORAGE_TIMEOUT_MS = 1_000;
const ANTI_FLOOD_TRANSPORT_TIMEOUT_MS = 900;
const ANTI_FLOOD_CLEANUP_INTERVAL_MS = 60_000;
const ANTI_FLOOD_CLEANUP_BATCH_SIZE = 25;
const antiFloodStorage = new Storage({
	...operationalStorageOptions,
	timeout: ANTI_FLOOD_TRANSPORT_TIMEOUT_MS,
	retryOptions: {
		autoRetry: false,
		maxRetries: 0,
		totalTimeout: ANTI_FLOOD_TRANSPORT_TIMEOUT_MS,
	},
});
const antiFloodBucket = antiFloodStorage.bucket(
	process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID,
);

async function runAntiFloodStorageRequest(startRequest, signal) {
	if (signal?.aborted) throw signal.reason;
	const request = startRequest();
	const cancel = () => {
		for (const method of ["abort", "cancel", "destroy"]) {
			if (typeof request?.[method] === "function") {
				request[method](signal.reason);
				break;
			}
		}
	};
	signal?.addEventListener("abort", cancel, { once: true });
	try {
		return await request;
	} finally {
		signal?.removeEventListener("abort", cancel);
	}
}

async function withinAntiFloodStorageDeadline(operation, {
	timeoutMs = ANTI_FLOOD_STORAGE_TIMEOUT_MS,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let timeoutHandle;
	const controller = new AbortController();
	try {
		const deadline = new Promise((_, reject) => {
			timeoutHandle = setTimeoutImpl(
				() => {
					const error = new Error("Anti-flood shared storage deadline exceeded");
					controller.abort(error);
					reject(error);
				},
				timeoutMs,
			);
			timeoutHandle?.unref?.();
		});
		return await Promise.race([
			Promise.resolve().then(() => operation(controller.signal)),
			deadline,
		]);
	} finally {
		if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
	}
}
function antiFloodFile(scope, key) {
	const digest = createHash("sha256").update(`${scope}\0${key}`).digest("hex");
	return antiFloodBucket.file(`anti-flood/${scope}/${digest}.json`);
}

async function readAntiFloodState(file, signal) {
	for (let attempt = 0; attempt < 3; attempt += 1) {
		try {
			const [metadata] = await runAntiFloodStorageRequest(
				() => file.getMetadata(),
				signal,
			);
			const generation = Number(metadata.generation);
			const [contents] = await runAntiFloodStorageRequest(
				() => file.download({
					preconditionOpts: { ifGenerationMatch: generation },
				}),
				signal,
			);
			return {
				state: JSON.parse(contents.toString("utf8")),
				generation,
			};
		} catch (error) {
			if (isStorageError(error, 404)) return null;
			if (isStorageError(error, 412)) continue;
			throw error;
		}
	}
	throw new Error("Anti-flood state changed repeatedly while reading");
}

function antiFloodStateExpiresAt(state, { windowMs, strikeWindowMs }) {
	const eventExpiry = (Array.isArray(state.events) ? state.events : [])
		.reduce((latest, event) => Math.max(latest, Number(event?.at) + windowMs || 0), 0);
	const strikeExpiry = (Array.isArray(state.strikes) ? state.strikes : [])
		.reduce((latest, at) => Math.max(latest, Number(at) + strikeWindowMs || 0), 0);
	return Math.max(Number(state.blockedUntil) || 0, eventExpiry, strikeExpiry);
}

export async function cleanupExpiredAntiFloodStates(
	scope,
	{
		now = Date.now(),
		batchSize = ANTI_FLOOD_CLEANUP_BATCH_SIZE,
		bucket = antiFloodBucket,
		cursor = null,
		...deadlineOptions
	} = {},
) {
	return withinAntiFloodStorageDeadline(async signal => {
		const safeBatchSize = Math.max(1, Math.min(100, Number(batchSize) || ANTI_FLOOD_CLEANUP_BATCH_SIZE));
		const [files, nextQuery] = await runAntiFloodStorageRequest(
			() => bucket.getFiles({
				prefix: `anti-flood/${scope}/`,
				maxResults: safeBatchSize,
				autoPaginate: false,
				...(cursor?.pageToken ? { pageToken: cursor.pageToken } : {}),
			}),
			signal,
		);
		if (signal.aborted) throw signal.reason;
		if (cursor) cursor.pageToken = nextQuery?.pageToken || null;
		let removed = 0;
		await Promise.all((files || []).slice(0, safeBatchSize).map(async file => {
			const current = await readAntiFloodState(file, signal);
			if (!current) return;
			const storedExpiresAt = Number(current.state?.expiresAt);
			const expiresAt = Number.isFinite(storedExpiresAt)
				? storedExpiresAt
				: antiFloodStateExpiresAt(current.state || {}, {
					windowMs: 10_000,
					strikeWindowMs: 5 * 60_000,
				});
			if (expiresAt > now) return;
			try {
				await runAntiFloodStorageRequest(
					() => file.delete({
						preconditionOpts: { ifGenerationMatch: current.generation },
					}),
					signal,
				);
				if (signal.aborted) throw signal.reason;
				removed += 1;
			} catch (error) {
				if (!isStorageError(error, 404) && !isStorageError(error, 412)) throw error;
			}
		}));
		return removed;
	}, deadlineOptions);
}

export function startAntiFloodCleanupScheduler({
	scopes = ["session", "connection"],
	intervalMs = ANTI_FLOOD_CLEANUP_INTERVAL_MS,
	cleanup = cleanupExpiredAntiFloodStates,
	now = () => Date.now(),
	setIntervalImpl = setInterval,
	onError = (scope, error) => {
		console.warn(`[anti-flood] shared-state cleanup failed for ${scope}:`, error?.message);
	},
} = {}) {
	const statuses = new Map(scopes.map(scope => [scope, {
		running: false,
		pageToken: null,
	}]));
	const run = async () => {
		await Promise.all([...statuses].map(async ([scope, status]) => {
			if (status.running) return;
			status.running = true;
			try {
				await cleanup(scope, { now: now(), cursor: status });
			} catch (error) {
				onError(scope, error);
			} finally {
				status.running = false;
			}
		}));
	};
	const timer = setIntervalImpl(() => {
		void run();
	}, intervalMs);
	timer?.unref?.();
	return { run, timer };
}

startAntiFloodCleanupScheduler();

export async function coordinateFloodEvents(scope, key, incomingEvents, options = {}) {
	const {
		windowMs = 10_000,
		maxScore = 15,
		strikeWindowMs = 5 * 60_000,
		blockDurationsMs = [2_000, 10_000],
		banAfterStrikes = 3,
		banMs = 5 * 60_000,
		file = antiFloodFile(scope, key),
		...deadlineOptions
	} = options;
	const safeEvents = incomingEvents
		.map(event => ({
			at: Number(event?.at),
			weight: Math.max(0, Math.min(10, Number(event?.weight) || 0)),
		}))
		.filter(event => Number.isFinite(event.at));
	if (!safeEvents.length) return { action: "allow", blockedUntil: 0, strike: 0 };
	const now = Math.max(...safeEvents.map(event => event.at));

	return withinAntiFloodStorageDeadline(async signal => {
	for (let attempt = 0; attempt < 5; attempt += 1) {
		const current = await readAntiFloodState(file, signal);
		const state = current?.state || { events: [], strikes: [], blockedUntil: 0 };
		state.events = (Array.isArray(state.events) ? state.events : [])
			.filter(event => now - Number(event.at) < windowMs);
		state.strikes = (Array.isArray(state.strikes) ? state.strikes : [])
			.map(Number)
			.filter(at => now - at < strikeWindowMs);
		let action = state.blockedUntil > now ? "drop" : "allow";

		if (action === "allow") {
			state.events.push(...safeEvents);
			const score = state.events.reduce((sum, event) => sum + Number(event.weight || 0), 0);
			if (score > maxScore) {
				state.strikes.push(now);
				state.events = [];
				const strike = state.strikes.length;
				if (strike >= banAfterStrikes) {
					action = "ban";
					state.blockedUntil = now + banMs;
				} else {
					action = "block";
					const duration = blockDurationsMs[
						Math.min(strike - 1, blockDurationsMs.length - 1)
					] || 2_000;
					state.blockedUntil = now + duration;
				}
			}
		}
		state.expiresAt = antiFloodStateExpiresAt(state, { windowMs, strikeWindowMs });

		const body = JSON.stringify(state);
		try {
			await runAntiFloodStorageRequest(
				() => file.save(body, {
					contentType: "application/json",
					resumable: false,
					preconditionOpts: {
						ifGenerationMatch: current ? current.generation : 0,
					},
				}),
				signal,
			);
			if (signal.aborted) throw signal.reason;
			return {
				action,
				blockedUntil: Number(state.blockedUntil) || 0,
				strike: state.strikes.length,
			};
		} catch (error) {
			if (!isStorageError(error, 412)) throw error;
		}
	}
	throw new Error("Anti-flood coordination contention exceeded retry limit");
	}, deadlineOptions);
}

function promotionAlertCooldownFile(alertKey) {
	return operationalBucket.file(
		`operational-alert-cooldowns/${encodeURIComponent(alertKey)}.json`,
	);
}

function cooldownCoordinationHealthFile() {
	return operationalBucket.file(
		`operational-health/${COOLDOWN_COORDINATION_HEALTH_KEY}.json`,
	);
}

function isStorageError(error, code) {
	return Number(error?.code) === code;
}

function cooldownStorageError(operation, cause) {
	const error = new Error("Operational cooldown storage failed", { cause });
	error.cooldownOperation = operation;
	return error;
}

async function withinCooldownHealthDeadline(operation, {
	timeoutMs = COOLDOWN_HEALTH_STORAGE_TIMEOUT_MS,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let timeoutHandle;
	try {
		const deadline = new Promise((_, reject) => {
			timeoutHandle = setTimeoutImpl(
				() => reject(new Error("Cooldown health storage deadline exceeded")),
				timeoutMs,
			);
			timeoutHandle?.unref?.();
		});
		return await Promise.race([Promise.resolve().then(operation), deadline]);
	} finally {
		if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
	}
}

async function withinPromotionCooldownDeadline(operation, stage, {
	timeoutMs = PROMOTION_COOLDOWN_STORAGE_TIMEOUT_MS,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let timeoutHandle;
	try {
		const deadline = new Promise((_, reject) => {
			timeoutHandle = setTimeoutImpl(
				() => reject(cooldownStorageError(stage, new Error("deadline"))),
				timeoutMs,
			);
			timeoutHandle?.unref?.();
		});
		return await Promise.race([Promise.resolve().then(operation), deadline]);
	} finally {
		if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
	}
}

async function readPromotionAlertCooldown(file, deadlineOptions) {
	try {
		const [[contents], [metadata]] = await withinPromotionCooldownDeadline(
			() => Promise.all([file.download(), file.getMetadata()]),
			"load",
			deadlineOptions,
		);
		const parsed = JSON.parse(contents.toString("utf8"));
		const lastAlertAt = parsed?.lastAlertAt;
		const expiresAt = parsed?.expiresAt;
		if (
			typeof lastAlertAt !== "number"
			|| typeof expiresAt !== "number"
			|| !Number.isFinite(lastAlertAt)
			|| !Number.isFinite(expiresAt)
			|| expiresAt <= lastAlertAt
		) {
			throw new TypeError("Invalid operational cooldown timing state");
		}
		return {
			state: { lastAlertAt, expiresAt },
			generation: Number(metadata.generation),
		};
	} catch (error) {
		if (isStorageError(error, 404)) return null;
		throw cooldownStorageError("load", error);
	}
}

async function readCooldownCoordinationHealth(file) {
	for (let attempt = 0; attempt < 3; attempt += 1) {
		try {
			const [metadata] = await file.getMetadata();
			const generation = Number(metadata.generation);
			const [contents] = await file.download({
				preconditionOpts: { ifGenerationMatch: generation },
			});
			const parsed = JSON.parse(contents.toString("utf8"));
			if (
				!Number.isFinite(parsed?.failedAt)
				|| !COOLDOWN_COORDINATION_STAGES.has(parsed?.stage)
				|| Object.keys(parsed).some(key => key !== "failedAt" && key !== "stage")
			) {
				throw new TypeError("Invalid cooldown coordination health state");
			}
			return {
				state: { failedAt: parsed.failedAt, stage: parsed.stage },
				generation,
			};
		} catch (error) {
			if (isStorageError(error, 404)) return null;
			if (isStorageError(error, 412)) continue;
			throw error;
		}
	}
	throw new Error("Cooldown coordination health changed repeatedly while reading");
}

export async function loadSharedCooldownCoordinationHealth({
	healthyIntervalMs = 5 * 60_000,
	now = Date.now(),
	file = cooldownCoordinationHealthFile(),
	...deadlineOptions
} = {}) {
	return withinCooldownHealthDeadline(async () => {
		const current = await readCooldownCoordinationHealth(file);
		if (!current) return null;
		if (now - current.state.failedAt < healthyIntervalMs) return current.state;
		try {
			await file.delete({
				preconditionOpts: { ifGenerationMatch: current.generation },
			});
		} catch (error) {
			if (!isStorageError(error, 404) && !isStorageError(error, 412)) throw error;
		}
		return null;
	}, deadlineOptions);
}

export async function saveSharedCooldownCoordinationHealth(
	{ failedAt, stage },
	{ file = cooldownCoordinationHealthFile(), ...deadlineOptions } = {},
) {
	return withinCooldownHealthDeadline(async () => {
		const safeStage = COOLDOWN_COORDINATION_STAGES.has(stage) ? stage : "save";
		const safeFailedAt = Number.isFinite(failedAt) ? failedAt : Date.now();
		const body = JSON.stringify({ failedAt: safeFailedAt, stage: safeStage });
		for (let attempt = 0; attempt < 3; attempt += 1) {
			const current = await readCooldownCoordinationHealth(file);
			if (current?.state.failedAt > safeFailedAt) return;
			try {
				await file.save(body, {
					contentType: "application/json",
					resumable: false,
					preconditionOpts: {
						ifGenerationMatch: current ? current.generation : 0,
					},
				});
				return;
			} catch (error) {
				if (!isStorageError(error, 412)) throw error;
			}
		}
	}, deadlineOptions);
}

export async function clearSharedCooldownCoordinationHealth({
	succeededAt = Date.now(),
	file = cooldownCoordinationHealthFile(),
	...deadlineOptions
} = {}) {
	return withinCooldownHealthDeadline(async () => {
		for (let attempt = 0; attempt < 3; attempt += 1) {
			const current = await readCooldownCoordinationHealth(file);
			if (!current || current.state.failedAt > succeededAt) return;
			try {
				await file.delete({
					preconditionOpts: { ifGenerationMatch: current.generation },
				});
				return;
			} catch (error) {
				if (isStorageError(error, 404)) return;
				if (!isStorageError(error, 412)) throw error;
			}
		}
	}, deadlineOptions);
}

export async function loadSharedPromotionAlertCooldownState({
	alertKey = PERMANENT_PROMOTION_ALERT_KEY,
	now = Date.now(),
	file = promotionAlertCooldownFile(alertKey),
	...deadlineOptions
} = {}) {
	const current = await readPromotionAlertCooldown(file, deadlineOptions);
	if (!current?.state || current.state.expiresAt <= now) return null;
	return current.state;
}

export async function claimPromotionAlertCooldown(
	{ lastAlertAt, expiresAt },
	{
		alertKey = PERMANENT_PROMOTION_ALERT_KEY,
		file = promotionAlertCooldownFile(alertKey),
		...deadlineOptions
	} = {},
) {
	if (!Number.isFinite(lastAlertAt) || !Number.isFinite(expiresAt)) {
		throw new TypeError("Promotion alert cooldown claim requires finite timestamps");
	}
	const body = JSON.stringify({ lastAlertAt, expiresAt });

	for (let attempt = 0; attempt < 3; attempt += 1) {
		try {
			await withinPromotionCooldownDeadline(
				() => file.save(body, {
					contentType: "application/json",
					resumable: false,
					preconditionOpts: { ifGenerationMatch: 0 },
				}),
				"save",
				deadlineOptions,
			);
			return true;
		} catch (error) {
			if (!isStorageError(error, 412)) {
				throw cooldownStorageError("save", error);
			}
		}

		let current;
		try {
			current = await readPromotionAlertCooldown(file, deadlineOptions);
		} catch (error) {
			throw cooldownStorageError("load", error);
		}
		if (!current) return false;
		if (current?.state && current.state.expiresAt > lastAlertAt) return false;
		try {
			await withinPromotionCooldownDeadline(
				() => file.delete({
					preconditionOpts: {
						ifGenerationMatch: current.generation,
					},
				}),
				"cleanup",
				deadlineOptions,
			);
		} catch (error) {
			if (!isStorageError(error, 404) && !isStorageError(error, 412)) {
				throw cooldownStorageError("cleanup", error);
			}
		}
	}
	return false;
}

export async function removePromotionAlertCooldownState({
	alertKey = PERMANENT_PROMOTION_ALERT_KEY,
	file = promotionAlertCooldownFile(alertKey),
	...deadlineOptions
} = {}) {
	const current = await readPromotionAlertCooldown(file, deadlineOptions);
	if (!current) return;
	try {
		await withinPromotionCooldownDeadline(
			() => file.delete({
				preconditionOpts: { ifGenerationMatch: current.generation },
			}),
			"cleanup",
			deadlineOptions,
		);
	} catch (error) {
		if (isStorageError(error, 404) || isStorageError(error, 412)) return;
		throw cooldownStorageError("cleanup", error);
	}
}

export function normalizeCookieKey(cookie) {
	if (typeof cookie !== "string") return "";
	return cookie.replace(/\0/g, "�");
}

db.serialize(() => {
	db.run(`CREATE TABLE IF NOT EXISTS unlocked_hats (cookie TEXT, hat TEXT, PRIMARY KEY (cookie, hat))`);
	db.run(`CREATE TABLE IF NOT EXISTS active_asn_bans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	asn TEXT NOT NULL UNIQUE,
	reason TEXT NOT NULL
)`);
	db.run(`CREATE TABLE IF NOT EXISTS hard_bans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		reason TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ip, fingerprint)
	)`);
	db.run(`CREATE INDEX IF NOT EXISTS hard_bans_ip_idx ON hard_bans(ip)`);
	db.run(`CREATE INDEX IF NOT EXISTS hard_bans_fingerprint_idx ON hard_bans(fingerprint)`);
	db.run(`CREATE TABLE IF NOT EXISTS admin_logins (cookie TEXT PRIMARY KEY, godword TEXT)`);
	db.run(`CREATE TABLE IF NOT EXISTS server_safety_state (
		mode TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
	)`);
	db.run(`CREATE TABLE IF NOT EXISTS blocked_images (image TEXT PRIMARY KEY, reason TEXT)`);
	db.run(`CREATE TABLE IF NOT EXISTS user_joins (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, name TEXT, guid TEXT, cookie TEXT, headers TEXT)`);
	db.run(`CREATE TABLE IF NOT EXISTS message_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, name TEXT, type TEXT, data TEXT)`);
	db.run(`CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, time DATETIME DEFAULT CURRENT_TIMESTAMP)`);
	db.run(`CREATE TABLE IF NOT EXISTS ip_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_range TEXT UNIQUE, type TEXT, reason TEXT)`);
	db.run(`CREATE VIEW IF NOT EXISTS ip_block_view AS SELECT ip_range, type, reason FROM ip_blocks`);
	db.run(`CREATE TABLE IF NOT EXISTS active_bans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL,
		reason TEXT NOT NULL,
		expires_at INTEGER
	)`);
	db.run(`CREATE TABLE IF NOT EXISTS moderation_sanctions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		action TEXT NOT NULL CHECK (action IN ('mute', 'shadowban')),
		reason TEXT NOT NULL,
		expires_at INTEGER,
		UNIQUE(ip, action)
	)`);
	db.run(`CREATE INDEX IF NOT EXISTS moderation_sanctions_expiry_idx ON moderation_sanctions(expires_at)`);
	db.run(`CREATE TABLE IF NOT EXISTS audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		action TEXT NOT NULL,
		actor_name TEXT NOT NULL,
		actor_guid TEXT NOT NULL,
		target_name TEXT NOT NULL DEFAULT '',
		details TEXT NOT NULL DEFAULT ''
	)`);
});

function urlFilename(url) {
	try {
		return decodeURIComponent(new URL(url).pathname).replace(/^.+\//, "/");
	} catch {
		return "-1";
	}
}

export async function getUnlockedHats(cookie) {
	return new Promise((resolve, reject) => {
		db.all(
			`SELECT hat FROM unlocked_hats WHERE cookie = ?`,
			[sanitizeUnicode(cookie)],
			(err, rows) => {
				if (err) return reject(err);
				resolve(rows.map(row => row.hat));
			}
		);
	});
}

let tmdbSchemaReady = false;
let tmdbSchemaPromise = null;

function withTimeout(promise, ms, fallback) {
	return Promise.race([
		promise,
		new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
	]);
}

async function ensureTmdbSchema() {
	if (tmdbSchemaReady) return true;
	if (tmdbSchemaPromise) return tmdbSchemaPromise;
	tmdbSchemaPromise = withTimeout(client.query(`
		CREATE TABLE IF NOT EXISTS tmdb_events (
			id bigserial PRIMARY KEY,
			time timestamp NOT NULL DEFAULT now(),
			room text NOT NULL,
			guid text NOT NULL,
			name text NOT NULL DEFAULT '',
			type text NOT NULL,
			payload jsonb NOT NULL DEFAULT '{}'::jsonb
		);
		CREATE INDEX IF NOT EXISTS tmdb_events_time_idx ON tmdb_events (time);
		CREATE INDEX IF NOT EXISTS tmdb_events_room_time_idx ON tmdb_events (room, time);
		CREATE INDEX IF NOT EXISTS tmdb_events_guid_time_idx ON tmdb_events (guid, time);
	`).then(() => true).catch((e) => {
		console.error("[db] tmdb schema:", e?.message);
		return false;
	}), 1500, false).then((ok) => {
		tmdbSchemaReady = ok;
		return ok;
	}).finally(() => {
		tmdbSchemaPromise = null;
	});
	return tmdbSchemaPromise;
}
// fuck you stop logging me ut  you fucking pidor 
export async function logTmdbEvent(room, guid, name, type, payload) {
	if (!(await ensureTmdbSchema())) return;
	await client.query(`
		INSERT INTO tmdb_events (room, guid, name, type, payload)
		VALUES ($1, $2, $3, $4, $5::jsonb)
	`, [
		sanitizeUnicode(room || "default"),
		sanitizeUnicode(guid || ""),
		sanitizeUnicode(name || ""),
		sanitizeUnicode(type || ""),
		JSON.stringify(payload ?? {}),
	]).catch((e) => {
		console.error("[db] logTmdbEvent:", e?.message);
	});
}

export async function hasHat(cookie, hat) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT 1 FROM unlocked_hats WHERE cookie = ? AND hat = ?`,
			[sanitizeUnicode(cookie), hat],
			(err, row) => {
				if (err) return reject(err);
				resolve(!!row);
			}
		);
	});
}

export async function unlockHat(cookie, hat) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO unlocked_hats (cookie, hat) VALUES (?, ?) 
			 ON CONFLICT(cookie, hat) DO NOTHING`,
			[sanitizeUnicode(cookie), hat],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function setGodword(cookie, godword) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO admin_logins (cookie, godword) VALUES (?, ?) 
			 ON CONFLICT(cookie) DO UPDATE SET godword = excluded.godword`,
			[sanitizeUnicode(cookie), godword],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function deleteGodword(cookie) {
	return new Promise((resolve, reject) => {
		db.run(
			`DELETE FROM admin_logins WHERE cookie = ?`,
			[sanitizeUnicode(cookie)],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function logAuditEvent({ action, actorName, actorGuid, targetName = "", details = "" }) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO audit_events (action, actor_name, actor_guid, target_name, details)
			 VALUES (?, ?, ?, ?, ?)`,
			[
				sanitizeUnicode(String(action || "")).slice(0, 80),
				sanitizeUnicode(String(actorName || "")).slice(0, 120),
				sanitizeUnicode(String(actorGuid || "")).slice(0, 80),
				sanitizeUnicode(String(targetName || "")).slice(0, 120),
				sanitizeUnicode(String(details || "")).slice(0, 500),
			],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function getAuditEvents(limit = 25) {
	const safeLimit = Math.max(1, Math.min(100, Number(limit) || 25));
	return new Promise((resolve, reject) => {
		db.all(
			`SELECT created_at, action, actor_name, actor_guid, target_name, details
			 FROM audit_events ORDER BY id DESC LIMIT ?`,
			[safeLimit],
			(err, rows) => {
				if (err) return reject(err);
				resolve(rows || []);
			}
		);
	});
}

export async function getAuditEventsWithinDeadline(limit = 25, {
	timeoutMs = 1_000,
	loadEvents = getAuditEvents,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let timeoutHandle;
	try {
		const historyRead = Promise.resolve().then(() => loadEvents(limit));
		const deadline = new Promise((_, reject) => {
			timeoutHandle = setTimeoutImpl(() => reject(new Error("deadline")), timeoutMs);
			timeoutHandle?.unref?.();
		});
		return await Promise.race([historyRead, deadline]);
	} catch {
		// Audit history is observational; callers receive no database failure details.
		return null;
	} finally {
		if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
	}
}

export async function getDatabaseStats() {
	const tables = [
		"admin_logins", "audit_events", "blocked_images", "hard_bans",
		"ip_blocks", "message_logs", "user_joins",
	];
	const result = {};
	for (const table of tables) {
		result[table] = await new Promise((resolve, reject) => {
			db.get(`SELECT COUNT(*) AS count FROM ${table}`, [], (err, row) => {
				if (err) return reject(err);
				resolve(Number(row?.count) || 0);
			});
		});
	}
	return result;
}

export const DATABASE_STATS_SNAPSHOT_MAX_AGE_MS = 5 * 60 * 1_000;
const databaseStatsSnapshotStore = { current: null };
const DATABASE_STAT_KEYS = [
	"admin_logins", "audit_events", "blocked_images", "hard_bans",
	"ip_blocks", "message_logs", "user_joins",
];

function sanitizeDatabaseStats(stats) {
	if (!stats || typeof stats !== "object") return null;
	return Object.fromEntries(DATABASE_STAT_KEYS.map(key => [
		key,
		Math.max(0, Number(stats[key]) || 0),
	]));
}

export async function getDatabaseStatsWithinDeadline({
	timeoutMs = 1_000,
	loadStats = getDatabaseStats,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
	now = Date.now,
	maxSnapshotAgeMs = DATABASE_STATS_SNAPSHOT_MAX_AGE_MS,
	snapshotStore = databaseStatsSnapshotStore,
} = {}) {
	let timeoutHandle;
	try {
		const statsRead = Promise.resolve().then(() => loadStats());
		const deadline = new Promise((_, reject) => {
			timeoutHandle = setTimeoutImpl(() => reject(new Error("deadline")), timeoutMs);
			timeoutHandle?.unref?.();
		});
		const stats = sanitizeDatabaseStats(await Promise.race([statsRead, deadline]));
		if (!stats) throw new Error("invalid statistics");
		snapshotStore.current = {
			stats: { ...stats },
			capturedAt: now(),
		};
		return stats;
	} catch {
		// Server status is observational; database failures must not hide live status.
		const snapshot = snapshotStore.current;
		const ageMs = snapshot ? Math.max(0, now() - snapshot.capturedAt) : Infinity;
		if (!snapshot || ageMs > maxSnapshotAgeMs) return null;
		return {
			...snapshot.stats,
			stale: true,
			ageMs,
		};
	} finally {
		if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
	}
}

const SERVER_SAFETY_MODES = new Set(["maintenance", "emergency_lockdown"]);

function validateSafetyMode(mode) {
	if (!SERVER_SAFETY_MODES.has(mode)) {
		throw new TypeError(`Unknown server safety mode: ${mode}`);
	}
	return mode;
}

export async function setServerSafetyMode(mode, enabled) {
	const safeMode = validateSafetyMode(mode);
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO server_safety_state (mode, enabled) VALUES (?, ?)
			 ON CONFLICT(mode) DO UPDATE SET enabled = excluded.enabled`,
			[safeMode, enabled ? 1 : 0],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function loadServerSafetyState() {
	return new Promise((resolve, reject) => {
		db.all(
			`SELECT mode, enabled FROM server_safety_state
			 WHERE mode IN ('maintenance', 'emergency_lockdown')`,
			[],
			(err, rows) => {
				if (err) return reject(err);
				const state = {
					maintenance: false,
					emergencyLockdown: false,
				};
				for (const row of rows || []) {
					if (row.mode === "maintenance") state.maintenance = row.enabled === 1;
					if (row.mode === "emergency_lockdown") state.emergencyLockdown = row.enabled === 1;
				}
				resolve(state);
			}
		);
	});
}

// Keep the ten newest recovery points. Pruning happens only after VACUUM INTO
// succeeds, and the snapshot created by the current operation is always kept.
export const DATABASE_SNAPSHOT_RETENTION_COUNT = 10;
export const DATABASE_SNAPSHOT_TIMEOUT_MS = 15_000;

export async function pruneDatabaseSnapshots(
	snapshotDir,
	{
		retentionCount = DATABASE_SNAPSHOT_RETENTION_COUNT,
		protectedSnapshotPath = null,
	} = {},
) {
	const entries = await readdir(snapshotDir, { withFileTypes: true });
	const snapshots = entries
		.filter(entry => entry.isFile() && /^bonziworld-\d{4}-\d{2}-\d{2}T.+\.db$/.test(entry.name))
		.map(entry => path.join(snapshotDir, entry.name))
		.sort((left, right) => path.basename(right).localeCompare(path.basename(left)));
	const protectedPath = protectedSnapshotPath ? path.resolve(protectedSnapshotPath) : null;
	const keep = new Set();
	if (protectedPath && snapshots.some(snapshot => path.resolve(snapshot) === protectedPath)) {
		keep.add(protectedPath);
	}
	for (const snapshot of snapshots) {
		if (keep.size >= retentionCount) break;
		keep.add(path.resolve(snapshot));
	}
	const removed = [];
	for (const snapshot of snapshots) {
		if (keep.has(path.resolve(snapshot))) continue;
		await unlink(snapshot);
		removed.push(snapshot);
	}
	return removed;
}

export async function createDatabaseSnapshot() {
	const snapshotDir = path.join(__dirname, "snapshots");
	await mkdir(snapshotDir, { recursive: true });
	const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
	const snapshotPath = path.join(snapshotDir, `bonziworld-${timestamp}.db`);
	const escapedPath = snapshotPath.replaceAll("'", "''");
	await new Promise((resolve, reject) => {
		db.run(`VACUUM INTO '${escapedPath}'`, [], (err) => {
			if (err) return reject(err);
			resolve();
		});
	});
	await pruneDatabaseSnapshots(snapshotDir, { protectedSnapshotPath: snapshotPath });
	return snapshotPath;
}

export async function createDatabaseSnapshotWithinDeadline({
	createSnapshot = createDatabaseSnapshot,
	timeoutMs = DATABASE_SNAPSHOT_TIMEOUT_MS,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let timeoutHandle;
	const snapshot = Promise.resolve().then(createSnapshot);
	const deadline = new Promise((_, reject) => {
		timeoutHandle = setTimeoutImpl(
			() => reject(new Error("Database snapshot deadline exceeded")),
			timeoutMs,
		);
		timeoutHandle?.unref?.();
	});
	try {
		return await Promise.race([snapshot, deadline]);
	} finally {
		clearTimeoutImpl(timeoutHandle);
	}
}

export async function resetApplicationData() {
	const tables = [
		"unlocked_hats",
		"active_asn_bans",
		"hard_bans",
		"admin_logins",
		"blocked_images",
		"user_joins",
		"message_logs",
		"logs",
		"ip_blocks",
		"active_bans",
		"moderation_sanctions",
		"audit_events",
	];
	const statements = tables.map(table => `DELETE FROM ${table};`).join("\n");
	return new Promise((resolve, reject) => {
		db.exec(`BEGIN IMMEDIATE;\n${statements}\nDELETE FROM sqlite_sequence;\nCOMMIT;`, (err) => {
			if (err) {
				db.exec("ROLLBACK;", () => reject(err));
				return;
			}
			resolve();
		});
	});
}

export async function snapshotAndResetApplicationData({
	createSnapshot = createDatabaseSnapshot,
	resetData = resetApplicationData,
} = {}) {
	const snapshotPath = await createSnapshot();
	await resetData();
	return snapshotPath;
}

export async function getImageBlockReason(url) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT reason FROM blocked_images WHERE image = ?`,
			[sanitizeUnicode(urlFilename(url))],
			(err, row) => {
				if (err) return reject(err);
				resolve(row?.reason ?? null);
			}
		);
	});
}

export async function blockImage(url, reason) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO blocked_images (image, reason) VALUES (?, ?) 
			 ON CONFLICT(image) DO UPDATE SET reason = excluded.reason`,
			[sanitizeUnicode(urlFilename(url)), sanitizeUnicode(reason)],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function unblockImage(url) {
	return new Promise((resolve, reject) => {
		db.run(
			`DELETE FROM blocked_images WHERE image = ?`,
			[sanitizeUnicode(urlFilename(url))],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function getMessageIdsFromIp(ip) {
	return new Promise((resolve, reject) => {
		db.all(
			`SELECT m.id FROM message_logs m
			 JOIN user_joins u ON m.user_id = u.id
			 WHERE u.ip = ?
			 ORDER BY m.id DESC
			 LIMIT 50`,
			[ip],
			(err, rows) => {
				if (err) return reject(err);
				resolve(rows.map(row => row.id));
			}
		);
	});
}

export async function blockInfo(ip) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT type, reason FROM ip_block_view 
			 WHERE ? LIKE ip_range || '%' 
			 ORDER BY type DESC LIMIT 1`,
			[ip],
			(err, row) => {
				if (err) return reject(err);
				resolve(row || null);
			}
		);
	});
}

export async function saveAsnBan(asn, reason) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO active_asn_bans (asn, reason)
			 VALUES (?, ?)
			 ON CONFLICT(asn) DO UPDATE SET reason = excluded.reason`,
			[asn, sanitizeUnicode(reason)],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function removeAsnBan(asn) {
	return new Promise((resolve, reject) => {
		db.run(`DELETE FROM active_asn_bans WHERE asn = ?`, [asn], (err) => {
			if (err) return reject(err);
			resolve();
		});
	});
}

export async function getActiveAsnBans() {
	return new Promise((resolve, reject) => {
		db.all(`SELECT asn, reason FROM active_asn_bans`, [], (err, rows) => {
			if (err) return reject(err);
			resolve(rows || []);
		});
	});
}

export async function getAsnFromIp(ip) {
	if (!ip || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("192.168.") || ip.startsWith("10.")) {
		return "This IP is local, This might be a bug.";
	}

	try {
		const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
		if (res.ok) {
			const data = await res.json();
			if (data && data.success && data.connection && data.connection.asn) {
				let asnStr = String(data.connection.asn).trim().toUpperCase();
				return asnStr.startsWith("AS") ? asnStr : "AS" + asnStr;
			}
		}
	} catch (err) {}

	try {
		const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/asn/`);
		if (res.ok) {
			const asn = await res.text();
			if (asn && asn.trim() && !asn.includes("<html")) {
				let cleanAsn = asn.trim().toUpperCase();
				return cleanAsn.startsWith("AS") ? cleanAsn : "AS" + cleanAsn;
			}
		}
	} catch (err) {}

	return null;
}

export async function saveBan(ip, reason, expiresAt = null) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO active_bans (ip, type, reason, expires_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(ip) DO UPDATE SET
			 type = excluded.type,
			 reason = excluded.reason,
			 expires_at = excluded.expires_at`,
			[ip, expiresAt ? "temp" : "perm", sanitizeUnicode(reason), expiresAt ?? null],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function removeBan(ip) {
	return new Promise((resolve, reject) => {
		db.run(`DELETE FROM active_bans WHERE ip = ?`, [ip], (err) => {
			if (err) return reject(err);
			resolve();
		});
	});
}

export async function removeBanIfExpiry(ip, expectedExpiresAt) {
	return new Promise((resolve, reject) => {
		db.run(
			`DELETE FROM active_bans WHERE ip = ? AND expires_at = ?`,
			[ip, expectedExpiresAt],
			function(err) {
				if (err) return reject(err);
				resolve(this.changes || 0);
			}
		);
	});
}

export async function loadActiveBans() {
	return new Promise((resolve, reject) => {
		db.run(`DELETE FROM active_bans WHERE expires_at IS NOT NULL AND expires_at <= ?`, [Date.now()], (err) => {
			if (err) return reject(err);
			db.all(`SELECT ip, type, reason, expires_at FROM active_bans`, [], (err2, rows) => {
				if (err2) return reject(err2);
				resolve(rows || []);
			});
		});
	});
}

export async function saveModerationSanction(ip, action, reason, expiresAt = null) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO moderation_sanctions (ip, action, reason, expires_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(ip, action) DO UPDATE SET
			 reason = excluded.reason,
			 expires_at = excluded.expires_at`,
			[ip, action, sanitizeUnicode(reason), expiresAt ?? null],
			(err) => err ? reject(err) : resolve()
		);
	});
}

export async function removeModerationSanction(ip, action, expectedExpiresAt) {
	return new Promise((resolve, reject) => {
		const conditional = expectedExpiresAt === undefined
			? `DELETE FROM moderation_sanctions WHERE ip = ? AND action = ?`
			: `DELETE FROM moderation_sanctions WHERE ip = ? AND action = ? AND expires_at = ?`;
		const params = expectedExpiresAt === undefined
			? [ip, action]
			: [ip, action, expectedExpiresAt];
		db.run(conditional, params, function(err) {
			if (err) return reject(err);
			resolve(this.changes || 0);
		});
	});
}

export async function loadModerationSanctions() {
	return new Promise((resolve, reject) => {
		db.run(
			`DELETE FROM moderation_sanctions WHERE expires_at IS NOT NULL AND expires_at <= ?`,
			[Date.now()],
			(err) => {
				if (err) return reject(err);
				db.all(
					`SELECT ip, action, reason, expires_at FROM moderation_sanctions`,
					[],
					(err2, rows) => err2 ? reject(err2) : resolve(rows || [])
				);
			}
		);
	});
}

export async function getActiveBans() {
	return new Promise((resolve, reject) => {
		db.all(`SELECT ip, type, reason, expires_at FROM active_bans`, [], (err, rows) => {
			if (err) return reject(err);
			resolve(rows || []);
		});
	});
}

export async function saveHardBan(ip, fingerprint, reason) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO hard_bans (ip, fingerprint, reason)
			 VALUES (?, ?, ?)
			 ON CONFLICT(ip, fingerprint) DO UPDATE SET reason = excluded.reason`,
			[ip, fingerprint, sanitizeUnicode(reason)],
			(err) => {
				if (err) return reject(err);
				resolve();
			}
		);
	});
}

export async function findHardBan(ip, fingerprint) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT ip, fingerprint, reason
			 FROM hard_bans
			 WHERE ip = ? OR fingerprint = ?
			 ORDER BY id DESC
			 LIMIT 1`,
			[ip, fingerprint],
			(err, row) => {
				if (err) return reject(err);
				resolve(row || null);
			}
		);
	});
}

export async function getHardBans() {
	return new Promise((resolve, reject) => {
		db.all(
			`SELECT ip, fingerprint, reason, created_at
			 FROM hard_bans
			 ORDER BY id DESC`,
			[],
			(err, rows) => {
				if (err) return reject(err);
				resolve(rows || []);
			}
		);
	});
}

export async function removeHardBan(ip, fingerprint) {
	return new Promise((resolve, reject) => {
		db.run(
			`DELETE FROM hard_bans WHERE ip = ? OR fingerprint = ?`,
			[ip, fingerprint],
			function(err) {
				if (err) return reject(err);
				resolve(this.changes || 0);
			}
		);
	});
}

export async function logJoin(ip, name, guid, cookie, headers) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO user_joins (ip, name, guid, cookie, headers) VALUES (?, ?, ?, ?, ?)`,
			[ip, sanitizeUnicode(name), guid, sanitizeUnicode(cookie), sanitizeUnicode(headers)],
			function(err) {
				if (err) return reject(err);
				resolve(this.lastID.toString());
			}
		);
	});
}

export async function logMessage(databaseId, name, type, data) {
	return new Promise((resolve, reject) => {
		db.run(
			`INSERT INTO message_logs (user_id, name, type, data) VALUES (?, ?, ?, ?)`,
			[databaseId, sanitizeUnicode(name), type, sanitizeUnicode(data)],
			function(err) {
				if (err) return reject(err);
				resolve(this.lastID.toString());
			}
		);
	});
}

export async function getGodword(cookie) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT godword FROM admin_logins WHERE cookie = ?`,
			[cookie],
			(err, row) => {
				if (err) return reject(err);
				resolve(row?.godword ?? null);
			}
		);
	});
}

export async function getIpFromMessageId(msgId) {
	return new Promise((resolve, reject) => {
		db.get(
			`SELECT ip FROM message_logs WHERE id = ?`,
			[msgId],
			(err, row) => {
				if (err) return reject(err);
				resolve(row?.ip ?? null);
			}
		);
	});
}
