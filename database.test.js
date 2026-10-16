import test from "node:test";
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import {
	mkdtemp,
	readFile,
	readdir,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import settings from "./settings.json" with { type: "json" };
import {
	claimPromotionAlertCooldown,
	clearSharedCooldownCoordinationHealth,
	cleanupExpiredAntiFloodStates,
	coordinateFloodEvents,
	DATABASE_SNAPSHOT_RETENTION_COUNT,
	DATABASE_SNAPSHOT_TIMEOUT_MS,
	createDatabaseSnapshotWithinDeadline,
	findHardBan,
	getHardBans,
	getAuditEventsWithinDeadline,
	getDatabaseStatsWithinDeadline,
	loadSharedPromotionAlertCooldownState,
	loadSharedCooldownCoordinationHealth,
	loadServerSafetyState,
	normalizeCookieKey,
	pruneDatabaseSnapshots,
	removePromotionAlertCooldownState,
	removeHardBan,
	saveHardBan,
	saveSharedCooldownCoordinationHealth,
	setServerSafetyMode,
	startAntiFloodCleanupScheduler,
	snapshotAndResetApplicationData,
} from "./database.js";
import { canonicalizeIp } from "./iputil.js";
import { CoordinatedFloodGuard, WeightedFloodGuard } from "./antiFlood.js";
import {
	PowConfig,
	createPowChallenge,
	verifyPowProof,
	verifyPowSolution,
} from "./pow.js";
import { getPublicRankFlags } from "./rankIcons.js";
import {
	attachSharedObjectStorage,
	createGenerationAwareSharedObject,
} from "./test-fixtures/generationAwareSharedObject.js";
import { runWorkerCommand } from "./test-fixtures/boundedIpc.js";
import {
	canBypassOwnerLockdown,
	canRunServerManagementCommand,
	createCooldownCoordinationHealth,
	createCooldownStorageDiagnosticReporter,
	createGodmodeCommandHandlers,
	createLiveCooldownCoordinationHealth,
	createPermanentPromotionFailureReporter,
	createServerStatusCommandHandler,
	dispatchUserCommandHandler,
	formatCommandLog,
	notifyBigOwnersOfCooldownCoordinationFailure,
	parseMassDemoteRequest,
	resolveUserCommandHandler,
	ResetConfirmationGate,
	restorePermanentPromotionAlertCooldown,
	routeRestoredSafetyLogin,
	runGodmodePromotion,
	selectMassDemoteTargets,
	restoredSafetyOwnerNotice,
	restoredSafetyStartupMessage,
	SERVER_MANAGEMENT_COMMANDS,
	validateUserCommandTable,
} from "./ownerSafety.js";
import {
	createSafetyActivationCommandHandlers,
	sendPermanentPromotionFailureAlert,
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

test("PowConfig is frozen and signed proofs are valid only for the solving IP", () => {
	assert.equal(Object.isFrozen(PowConfig), true);
	const secret = "test-only-session-secret";
	const challenge = createPowChallenge({
		headers: { "user-agent": "Mozilla/5.0 Chrome/120" },
		ip: "203.0.113.10",
		level: 1,
		secret,
	});
	assert.equal(challenge.difficulty, PowConfig.minDifficulty);

	const prefix = "0".repeat(challenge.difficulty);
	let nonce = 0;
	while (!createHash("sha256").update(`${challenge.seed}${nonce}`).digest("hex").startsWith(prefix)) nonce++;
	const proof = verifyPowSolution({
		...challenge,
		nonce: String(nonce),
		ip: "203.0.113.10",
		secret,
	});

	assert.equal(typeof proof, "string");
	assert.equal(verifyPowProof({ proof, ip: "203.0.113.10", secret }), true);
	assert.equal(verifyPowProof({ proof, ip: "203.0.113.11", secret }), false);
	assert.equal(verifyPowSolution({
		...challenge,
		nonce: "not-a-number",
		ip: "203.0.113.10",
		secret,
	}), null);
});

test("weighted flood guard escalates bursts from a short pause to a temporary ban", () => {
	const guard = new WeightedFloodGuard({
		windowMs: 100,
		maxScore: 2,
		strikeWindowMs: 1_000,
		blockDurationsMs: [10, 20],
		banAfterStrikes: 3,
		banMs: 300,
	});

	assert.equal(guard.check("ip", 1, 0).action, "allow");
	assert.equal(guard.check("ip", 1, 1).action, "allow");
	assert.deepEqual(guard.check("ip", 1, 2), { action: "block", retryAfterMs: 10, strike: 1 });
	assert.equal(guard.check("ip", 1, 3).action, "drop");

	assert.equal(guard.check("ip", 1, 12).action, "allow");
	assert.equal(guard.check("ip", 1, 13).action, "allow");
	assert.deepEqual(guard.check("ip", 1, 14), { action: "block", retryAfterMs: 20, strike: 2 });

	assert.equal(guard.check("ip", 1, 34).action, "allow");
	assert.equal(guard.check("ip", 1, 35).action, "allow");
	assert.deepEqual(guard.check("ip", 1, 36), { action: "ban", banMs: 300, strike: 3 });
	assert.equal(guard.states.has("ip"), false);
});

function createGenerationFile() {
	const sharedObject = createGenerationAwareSharedObject();
	return Object.assign(sharedObject.file, { read: sharedObject.read });
}

test("generation-aware shared objects allow create-if-absent after deletion", async () => {
	const file = createGenerationFile();
	await file.save(JSON.stringify("first"), { preconditionOpts: { ifGenerationMatch: 0 } });
	const [{ generation }] = await file.getMetadata();
	await file.delete({ preconditionOpts: { ifGenerationMatch: generation } });

	await file.save(JSON.stringify("second"), { preconditionOpts: { ifGenerationMatch: 0 } });

	assert.deepEqual(file.read(), "second");
});

test("shared flood cleanup removes only expired records in a bounded batch", async () => {
	const expired = createGenerationFile();
	const activeStrike = createGenerationFile();
	const activeBlock = createGenerationFile();
	await expired.save(JSON.stringify({ expiresAt: 99 }), { preconditionOpts: { ifGenerationMatch: 0 } });
	await activeStrike.save(JSON.stringify({ expiresAt: 101 }), { preconditionOpts: { ifGenerationMatch: 0 } });
	await activeBlock.save(JSON.stringify({ expiresAt: 150, blockedUntil: 150 }), { preconditionOpts: { ifGenerationMatch: 0 } });
	const files = [expired, activeStrike, activeBlock];
	const bucket = {
		async getFiles(options) {
			assert.equal(options.maxResults, 2);
			assert.equal(options.autoPaginate, false);
			return [files.slice(0, options.maxResults)];
		},
	};

	assert.equal(await cleanupExpiredAntiFloodStates("session", {
		now: 100,
		batchSize: 2,
		bucket,
	}), 1);
	assert.equal(expired.read(), null);
	assert.deepEqual(activeStrike.read(), { expiresAt: 101 });
	assert.deepEqual(activeBlock.read(), { expiresAt: 150, blockedUntil: 150 });
});

test("shared flood cleanup advances through bounded storage pages", async () => {
	const cursor = {};
	const bucket = {
		async getFiles(options) {
			if (!options.pageToken) return [[], { pageToken: "next-page" }];
			assert.equal(options.pageToken, "next-page");
			return [[], null];
		},
	};

	await cleanupExpiredAntiFloodStates("session", { bucket, cursor });
	assert.equal(cursor.pageToken, "next-page");
	await cleanupExpiredAntiFloodStates("session", { bucket, cursor });
	assert.equal(cursor.pageToken, null);
});

test("shared flood cleanup removes expired legacy records conservatively", async () => {
	const expired = createGenerationFile();
	const activeStrike = createGenerationFile();
	await expired.save(JSON.stringify({
		events: [{ at: 1, weight: 1 }],
		strikes: [],
		blockedUntil: 0,
	}), { preconditionOpts: { ifGenerationMatch: 0 } });
	await activeStrike.save(JSON.stringify({
		events: [],
		strikes: [100],
		blockedUntil: 0,
	}), { preconditionOpts: { ifGenerationMatch: 0 } });
	const bucket = { async getFiles() { return [[expired, activeStrike]]; } };

	assert.equal(await cleanupExpiredAntiFloodStates("session", {
		now: 10_002,
		bucket,
	}), 1);
	assert.equal(expired.read(), null);
	assert.notEqual(activeStrike.read(), null);
});

test("recurring shared flood cleanup removes idle records without another write", async () => {
	const file = createGenerationFile();
	await file.save(JSON.stringify({ expiresAt: 100 }), {
		preconditionOpts: { ifGenerationMatch: 0 },
	});
	let now = 50;
	let intervalCallback;
	const bucket = { async getFiles() { return [[file]]; } };
	const scheduler = startAntiFloodCleanupScheduler({
		scopes: ["session"],
		now: () => now,
		cleanup: (scope, options) => cleanupExpiredAntiFloodStates(scope, {
			...options,
			bucket,
		}),
		setIntervalImpl(callback, delay) {
			assert.equal(delay, 60_000);
			intervalCallback = callback;
			return { unref() {} };
		},
	});

	await scheduler.run();
	assert.notEqual(file.read(), null);
	now = 101;
	await intervalCallback();
	await new Promise(resolve => setImmediate(resolve));
	assert.equal(file.read(), null);
});

test("shared flood cleanup cannot delete a record updated by another server", async () => {
	let body = JSON.stringify({ expiresAt: 50 });
	let generation = 1;
	const file = {
		async download() {
			return [Buffer.from(body)];
		},
		async getMetadata() {
			return [{ generation: String(generation) }];
		},
		async delete({ preconditionOpts }) {
			body = JSON.stringify({ expiresAt: 200, strikes: [100] });
			generation += 1;
			if (Number(preconditionOpts.ifGenerationMatch) !== generation) {
				throw Object.assign(new Error("changed"), { code: 412 });
			}
		},
	};
	const bucket = { async getFiles() { return [[file]]; } };

	assert.equal(await cleanupExpiredAntiFloodStates("session", { now: 100, bucket }), 0);
	assert.deepEqual(JSON.parse(body), { expiresAt: 200, strikes: [100] });
});

test("shared flood cleanup reads and deletes the same object generation", async () => {
	let body = JSON.stringify({ expiresAt: 50 });
	let generation = 1;
	let replaced = false;
	let deleted = false;
	const file = {
		async getMetadata() {
			return [{ generation: String(generation) }];
		},
		async download({ preconditionOpts }) {
			if (!replaced) {
				body = JSON.stringify({ expiresAt: 200, strikes: [100] });
				generation += 1;
				replaced = true;
			}
			if (Number(preconditionOpts.ifGenerationMatch) !== generation) {
				throw Object.assign(new Error("changed"), { code: 412 });
			}
			return [Buffer.from(body)];
		},
		async delete() {
			deleted = true;
		},
	};
	const bucket = { async getFiles() { return [[file]]; } };

	assert.equal(await cleanupExpiredAntiFloodStates("session", { now: 100, bucket }), 0);
	assert.equal(deleted, false);
	assert.deepEqual(JSON.parse(body), { expiresAt: 200, strikes: [100] });
});

test("coordinated flood records expire after every active event, strike, and block", async () => {
	const file = createGenerationFile();
	await coordinateFloodEvents("session", "ip", [{ at: 10, weight: 1 }], {
		windowMs: 100,
		strikeWindowMs: 1_000,
		file,
	});
	assert.equal(file.read().expiresAt, 110);

	await coordinateFloodEvents("session", "ip", [{ at: 20, weight: 10 }], {
		windowMs: 100,
		maxScore: 1,
		strikeWindowMs: 1_000,
		blockDurationsMs: [50],
		file,
	});
	assert.equal(file.read().expiresAt, 1_020);
	assert.equal(file.read().blockedUntil, 70);
});

test("multiple server processes combine distributed bursts into one coherent block", async (t) => {
	const file = createGenerationFile();
	const options = {
		windowMs: 100,
		maxScore: 3,
		strikeWindowMs: 1_000,
		blockDurationsMs: [50],
		banAfterStrikes: 3,
		banMs: 500,
		file,
	};
	const workers = [0, 1].map(() => fork(
		new URL("./test-fixtures/coordinatedFloodWorker.js", import.meta.url),
		[],
		{ stdio: ["ignore", "ignore", "inherit", "ipc"] },
	));
	t.after(() => workers.forEach(worker => worker.kill()));

	const results = await Promise.all(workers.map((worker, workerIndex) => {
		worker.on("message", async message => {
			if (message.type === "coordinate") {
				try {
					const result = await coordinateFloodEvents("session", "ip", message.events, options);
					worker.send({ type: "coordinated", id: message.id, result });
				} catch {
					worker.kill();
				}
			}
		});
		return runWorkerCommand(worker, "coordinate flood events", {
			startAt: workerIndex * 2,
		});
	}));

	assert.equal(results.every(result => result.immediate.every(action => action === "allow")), true);
	assert.equal(results.some(result => result.sharedAction === "block"), true);
	assert.equal(results.some(result => result.afterFlush === "drop"), true);
});

test("dropped worker IPC replies fail within their deadlines and clean up", async (t) => {
	const spawnWorker = fixtureName => fork(
		new URL(`./test-fixtures/${fixtureName}`, import.meta.url),
		[],
		{
		stdio: ["ignore", "ignore", "inherit", "ipc"],
		env: {
			...process.env,
			TEST_IPC_REQUEST_TIMEOUT_MS: "30",
		},
		},
	);
	const stopWorker = async worker => {
		if (worker.exitCode !== null || worker.signalCode !== null) return;
		const exited = new Promise(resolve => worker.once("exit", resolve));
		worker.kill();
		await exited;
	};
	const assertWorkerCommandListenersRestored = (worker, baseline) => {
		for (const event of ["error", "exit", "message"]) {
			assert.equal(
				worker.listenerCount(event),
				baseline[event],
				`${event} listeners should be restored after rejection`,
			);
		}
	};

	await t.test("command replies", async () => {
		const worker = spawnWorker("coordinatedFloodWorker.js");
		t.after(() => stopWorker(worker));
		const baseline = Object.fromEntries(
			["error", "exit", "message"].map(event => [event, worker.listenerCount(event)]),
		);
		const privatePayload = "private-command-payload";
		let acknowledgeDrop;
		const dropped = new Promise(resolve => {
			acknowledgeDrop = message => {
				if (message.type === "replyDropped") resolve(message.id);
			};
			worker.on("message", acknowledgeDrop);
		});
		const startedAt = Date.now();
		const command = runWorkerCommand(
				worker,
				"drop command reply",
				{ operation: "dropCommandReply", payload: privatePayload },
				{ timeoutMs: 250 },
			);
		const droppedId = await dropped;
		assert.ok(Number.isInteger(droppedId), "worker should acknowledge dropping the reply");
		worker.off("message", acknowledgeDrop);
		await assert.rejects(
			command,
			error => {
				assert.match(error.message, /worker operation: drop command reply/);
				assert.doesNotMatch(error.message, new RegExp(privatePayload));
				return true;
			},
		);
		assert.ok(Date.now() - startedAt < 1_000);
		assertWorkerCommandListenersRestored(worker, baseline);
		await stopWorker(worker);
		assert.notEqual(worker.exitCode ?? worker.signalCode, null);
	});

	await t.test("shared-object storage replies", async () => {
		const worker = spawnWorker("cooldownHealthWorker.js");
		t.after(() => stopWorker(worker));
		const baseline = Object.fromEntries(
			["error", "exit", "message"].map(event => [event, worker.listenerCount(event)]),
		);
		const privatePayload = "private-storage-body";
		const dropStorageReply = message => {
			if (message.type === "storage") {
				assert.equal(message.operation, "save");
			}
		};
		worker.on("message", dropStorageReply);
		const startedAt = Date.now();
		await assert.rejects(
			runWorkerCommand(worker, "load shared cooldown health", {
				operation: "directStorageSave",
				body: privatePayload,
			}, { timeoutMs: 500 }),
			error => {
				assert.match(error.message, /shared-object save reply/);
				assert.doesNotMatch(error.message, new RegExp(privatePayload));
				return true;
			},
		);
		assert.ok(Date.now() - startedAt < 1_000);
		assertWorkerCommandListenersRestored(worker, {
			...baseline,
			message: baseline.message + 1,
		});
		worker.off("message", dropStorageReply);
		assertWorkerCommandListenersRestored(worker, baseline);
		const pendingResult = await runWorkerCommand(
			worker,
			"inspect shared-object pending requests",
			{ operation: "pendingCount" },
			{ timeoutMs: 500 },
		);
		assert.equal(pendingResult.result, 0);
		await stopWorker(worker);
		assert.notEqual(worker.exitCode ?? worker.signalCode, null);
	});

	await t.test("flood-coordination replies", async () => {
		const worker = spawnWorker("coordinatedFloodWorker.js");
		t.after(() => stopWorker(worker));
		const baseline = Object.fromEntries(
			["error", "exit", "message"].map(event => [event, worker.listenerCount(event)]),
		);
		const privatePayload = "private-flood-events";
		const dropCoordinateReply = message => {
			if (message.type === "coordinate") {
				assert.ok(Array.isArray(message.events));
			}
		};
		worker.on("message", dropCoordinateReply);
		const startedAt = Date.now();
		await assert.rejects(
			runWorkerCommand(worker, "coordinate flood events", {
				operation: "directCoordinate",
				events: [{ at: 0, weight: 1, payload: privatePayload }],
			}, { timeoutMs: 500 }),
			error => {
				assert.match(error.message, /coordinate flood reply/);
				assert.doesNotMatch(error.message, new RegExp(privatePayload));
				return true;
			},
		);
		assert.ok(Date.now() - startedAt < 1_000);
		assertWorkerCommandListenersRestored(worker, {
			...baseline,
			message: baseline.message + 1,
		});
		worker.off("message", dropCoordinateReply);
		assertWorkerCommandListenersRestored(worker, baseline);
		const pendingResult = await runWorkerCommand(
			worker,
			"inspect flood pending requests",
			{ operation: "pendingCount" },
			{ timeoutMs: 500 },
		);
		assert.equal(pendingResult.result, 0);
		await stopWorker(worker);
		assert.notEqual(worker.exitCode ?? worker.signalCode, null);
	});
});

test("shared automatic block deadlines expire consistently across guards", async () => {
	const file = createGenerationFile();
	let now = 10;
	const options = {
		windowMs: 100,
		maxScore: 1,
		blockDurationsMs: [50],
		banAfterStrikes: 3,
		file,
	};
	const coordinate = (_key, events) => coordinateFloodEvents("connection", "ip", events, options);
	const guards = [1, 2].map(() => new CoordinatedFloodGuard({
		guardOptions: options,
		coordinate,
		now: () => now,
		setTimeoutImpl: () => ({ unref() {} }),
	}));

	guards[0].check("ip", 1, now++);
	guards[1].check("ip", 1, now++);
	await guards[0].flush("ip");
	const result = await guards[1].flush("ip");
	assert.equal(result.blockedUntil, 61);
	assert.equal(guards[1].check("ip", 1, 60).action, "drop");
	assert.equal(guards[1].check("ip", 0, 61).action, "allow");
});

test("shared flood coordination falls back to responsive local protection after its deadline", async () => {
	const timer = createManualTimer();
	const errors = [];
	const guard = new CoordinatedFloodGuard({
		guardOptions: { maxScore: 1 },
		coordinate: (_key, events) => coordinateFloodEvents("session", "ip", events, {
			file: {
				getMetadata: () => new Promise(() => {}),
			},
			timeoutMs: 25,
			...timer,
		}),
		onSharedError: (_key, error) => errors.push(error.message),
		setTimeoutImpl: () => ({ unref() {} }),
	});

	assert.equal(guard.check("ip", 1, 0).action, "allow");
	const flush = guard.flush("ip");
	timer.advanceTo(25);
	assert.equal(await flush, null);
	assert.deepEqual(errors, ["Anti-flood shared storage deadline exceeded"]);
	assert.equal(guard.check("ip", 1, 1).action, "block");
});

test("a stalled shared flood cleanup releases its scheduler slot after the deadline", async () => {
	const timers = [createManualTimer(), createManualTimer()];
	let cleanupCalls = 0;
	const errors = [];
	const scheduler = startAntiFloodCleanupScheduler({
		scopes: ["session"],
		cleanup: scope => cleanupExpiredAntiFloodStates(scope, {
			bucket: {
				getFiles: () => new Promise(() => {}),
			},
			timeoutMs: 25,
			...timers[cleanupCalls++],
		}),
		onError: (_scope, error) => errors.push(error.message),
		setIntervalImpl: () => ({ unref() {} }),
	});

	const firstRun = scheduler.run();
	timers[0].advanceTo(25);
	await firstRun;
	const secondRun = scheduler.run();
	timers[1].advanceTo(25);
	await secondRun;

	assert.equal(cleanupCalls, 2);
	assert.deepEqual(errors, [
		"Anti-flood shared storage deadline exceeded",
		"Anti-flood shared storage deadline exceeded",
	]);
});

test("repeated shared flood timeouts cancel active storage requests without late writes", async () => {
	let activeRequests = 0;
	let aborts = 0;
	let saves = 0;
	const file = {
		getMetadata() {
			activeRequests += 1;
			const request = new Promise(() => {});
			request.abort = () => {
				activeRequests -= 1;
				aborts += 1;
			};
			return request;
		},
		async save() {
			saves += 1;
		},
	};

	for (let attempt = 0; attempt < 50; attempt += 1) {
		const timer = createManualTimer();
		const coordination = coordinateFloodEvents(
			"session",
			"ip",
			[{ at: attempt, weight: 1 }],
			{ file, timeoutMs: 5, ...timer },
		);
		await new Promise(resolve => setImmediate(resolve));
		assert.equal(activeRequests, 1);
		timer.advanceTo(5);
		await assert.rejects(coordination, /deadline exceeded/);
		assert.equal(activeRequests, 0);
	}

	assert.equal(aborts, 50);
	assert.equal(saves, 0);
});

test("repeated shared flood cleanup timeouts cancel active list requests", async () => {
	let activeRequests = 0;
	let aborts = 0;
	let cursorMutations = 0;
	const cursor = {
		get pageToken() {
			return null;
		},
		set pageToken(_value) {
			cursorMutations += 1;
		},
	};
	const bucket = {
		getFiles() {
			activeRequests += 1;
			const request = new Promise(() => {});
			request.abort = () => {
				activeRequests -= 1;
				aborts += 1;
			};
			return request;
		},
	};

	for (let attempt = 0; attempt < 50; attempt += 1) {
		const timer = createManualTimer();
		const cleanup = cleanupExpiredAntiFloodStates("session", {
			bucket,
			cursor,
			timeoutMs: 5,
			...timer,
		});
		await new Promise(resolve => setImmediate(resolve));
		assert.equal(activeRequests, 1);
		timer.advanceTo(5);
		await assert.rejects(cleanup, /deadline exceeded/);
		assert.equal(activeRequests, 0);
	}

	assert.equal(aborts, 50);
	assert.equal(cursorMutations, 0);
});

test("normalizeCookieKey sanitizes cookies consistently for godword persistence", () => {
	assert.equal(normalizeCookieKey("token-123"), "token-123");
	assert.equal(normalizeCookieKey("bad\u0000cookie"), "bad�cookie");
});

test("getPublicRankFlags exposes the god gavel at runlevel 4", () => {
	const flags = getPublicRankFlags(4);
	assert.equal(flags.runlevel, 4);
	assert.equal(flags.gavel, true);
	assert.equal(flags.crown, false);
});

test("getPublicRankFlags exposes Big Owner only at runlevel 8", () => {
	assert.equal(getPublicRankFlags(8).bigowner, true);
	assert.equal(getPublicRankFlags(7).bigowner, false);
	assert.equal(getPublicRankFlags(8).radical, false);
});

test("removed standalone role and IP-mask secrets cannot return through server wiring", async () => {
	const source = await readFile(new URL("./server.js", import.meta.url), "utf8");
	assert.equal(source.includes("RADICALGREEN"), false);
	assert.equal(source.includes("IP_MASK_SECRET"), false);
	assert.match(source, /allowedHashes:\s*\[bigOwnerWord\]\.filter\(Boolean\)/);
});

test("moderation commands use the current configured rank gates", () => {
	assert.equal(settings.runlevel.promote, 6);
	assert.equal(settings.runlevel.promotehighking, 6);
	assert.equal(settings.runlevel.info, 7);
	assert.equal(settings.runlevel.forcemessage, 6);
	assert.equal(settings.runlevel.blacklistcrosscolor, 2);
	assert.equal(settings.runlevel.unblacklistcrosscolor, 2);
	assert.equal(settings.runlevel.moderate, 2);
	assert.equal(settings.runlevel.mute, 3);
	assert.equal(settings.runlevel.shadowban, 4);
	assert.equal(settings.runlevel.unshadowban, 4);
});

test("crosscolors and crosshats are available to everyone", () => {
	assert.equal(settings.runlevel.crosscolor, 0);
	assert.equal(settings.runlevel.crosshat, 0);
});

test("demotion commands use developer-level rank gates", () => {
	assert.equal(settings.runlevel.demote, 6);
	assert.equal(settings.runlevel.demotehighking, 6);
});

test("restart command is restricted to the highest rank", () => {
	assert.equal(settings.runlevel.restart, 8);
	for (const command of [
		"serverstatus",
		"auditcenter",
		"maintenancemode",
		"emergencylockdown",
		"databasesnapshot",
		"resetdatabase",
		"promoteowner",
		"demoteowner",
		"massdemote",
	]) {
		assert.equal(settings.runlevel[command], 8, `${command} must require Big Owner`);
	}
});

test("mass demote parses all and bounded regex selectors with confirmation tokens", () => {
	assert.deepEqual(parseMassDemoteRequest("all"), {
		selector: "all",
		pattern: "",
		token: "",
	});
	assert.deepEqual(parseMassDemoteRequest("regex ^Alice$ --confirm abcdef123456"), {
		selector: "regex",
		pattern: "^Alice$",
		token: "abcdef123456",
	});
	assert.equal(parseMassDemoteRequest("regex (a+)+$").error, "Nested or repeated regex quantifiers are not allowed.");
	assert.equal(parseMassDemoteRequest("regex (?=owner)").error, "Backreferences and lookaround are not allowed in mass-demote regexes.");
	assert.equal(parseMassDemoteRequest("").error.includes("Usage:"), true);
});

test("mass demote confirmation tokens are redacted from command logs", () => {
	const logged = formatCommandLog("massdemote", "regex ^Alice$ --confirm abcdef123456");
	assert.equal(logged, "/massdemote regex ^Alice$ --confirm [REDACTED]");
	assert.equal(logged.includes("abcdef123456"), false);
});

test("mass demote selectors exclude the actor, regular users, and every Big Owner", () => {
	const actor = { runlevel: 8, public: { name: "Primary Owner" } };
	const users = [
		actor,
		{ runlevel: 8, public: { name: "Other Owner" }, runword: "owner" },
		{ runlevel: 7, public: { name: "Alice Owner" }, runword: "rank" },
		{ runlevel: 4, public: { name: "Alice Pope" }, runword: "rank" },
		{ runlevel: 0, public: { name: "Alice Regular" }, runword: null },
		{ runlevel: 3, public: { name: "Bob King" }, runword: "rank" },
	];
	assert.deepEqual(
		selectMassDemoteTargets(users, actor, parseMassDemoteRequest("regex ^Alice")),
		[users[2], users[3]]
	);
	assert.deepEqual(
		selectMassDemoteTargets(users, actor, parseMassDemoteRequest("all")),
		[users[2], users[3], users[5]]
	);
});

test("live protection commands remain responsive when alert delivery ignores abort", async () => {
	for (const testCase of [
		{
			command: "maintenancemode",
			stateKey: "maintenance",
			persistenceKey: "maintenance",
			notification: "Maintenance mode is now ON.",
		},
		{
			command: "emergencylockdown",
			stateKey: "emergencyLockdown",
			persistenceKey: "emergency_lockdown",
			notification: "Emergency lockdown is now ON.",
		},
	]) {
		const state = { maintenance: false, emergencyLockdown: false };
		const notifications = [];
		const persisted = [];
		let aborted = false;
		let followUpProcessed = false;
		const timeoutMs = 20;
		const timer = createManualTimer();
		const commands = {
			...createSafetyActivationCommandHandlers({
				getState: () => state,
				setState: (key, value) => {
					state[key] = value;
				},
				parseToggle: input => input === "on" ? true : null,
				persistMode: async (mode, enabled) => {
					persisted.push({ mode, enabled });
				},
				recordAction: () => {},
				listUsers: () => [],
				destination: "https://alerts.example.test/hanging",
				timeoutMs,
				setTimeoutImpl: timer.setTimeoutImpl,
				clearTimeoutImpl: timer.clearTimeoutImpl,
				fetchImpl: async (_url, { signal }) => new Promise(() => {
					signal.addEventListener("abort", () => {
						aborted = true;
						assert.equal(state[testCase.stateKey], true);
					}, { once: true });
				}),
			}),
			followup() {
				followUpProcessed = true;
			},
		};
		const user = {
			public: { name: "Big Owner" },
			notify: text => notifications.push(text),
		};
		const originalError = console.error;
		console.error = () => {};
		try {
			let commandCompleted = false;
			const command = dispatchUserCommandHandler(user, testCase.command, "on", 123, commands)
				.then(() => {
					commandCompleted = true;
				});
			await Promise.resolve();
			await Promise.resolve();

			assert.equal(aborted, false);
			assert.equal(commandCompleted, false);
			timer.advanceTo(timeoutMs);
			await command;
			await dispatchUserCommandHandler(user, "followup", "", 124, commands);

			assert.equal(aborted, true, `${testCase.command} did not abort alert delivery`);
			assert.equal(commandCompleted, true);
			assert.equal(state[testCase.stateKey], true);
			assert.deepEqual(persisted, [{ mode: testCase.persistenceKey, enabled: true }]);
			assert.deepEqual(notifications, [testCase.notification]);
			assert.equal(followUpProcessed, true);
		} finally {
			console.error = originalError;
		}
	}
});

test("emergency lockdown evicts regular users but keeps Big Owners connected before a stalled alert deadline", async () => {
	const state = { maintenance: false, emergencyLockdown: false };
	const regularEvents = [];
	let regularDisconnects = 0;
	let ownerDisconnects = 0;
	let alertAborted = false;
	let commandCompleted = false;
	let markAlertStarted;
	const timeoutMs = 20;
	const timer = createManualTimer();
	const alertStarted = new Promise(resolve => {
		markAlertStarted = resolve;
	});
	const regularUser = {
		runlevel: 0,
		socket: {
			emit(event, payload) {
				regularEvents.push({ event, payload });
			},
		},
		disconnect() {
			regularDisconnects += 1;
		},
	};
	const bigOwner = {
		runlevel: 8,
		socket: {
			emit() {
				assert.fail("Big Owner must not receive the lockdown kick");
			},
		},
		disconnect() {
			ownerDisconnects += 1;
		},
	};
	const commands = createSafetyActivationCommandHandlers({
		getState: () => state,
		setState: (key, value) => {
			state[key] = value;
		},
		parseToggle: input => input === "on" ? true : null,
		persistMode: async () => {},
		recordAction: () => {},
		listUsers: () => [regularUser, bigOwner],
		destination: "https://alerts.example.test/hanging",
		timeoutMs,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		fetchImpl: async (_url, { signal }) => new Promise(() => {
			markAlertStarted();
			signal.addEventListener("abort", () => {
				alertAborted = true;
			}, { once: true });
		}),
	});
	const actor = {
		public: { name: "Big Owner" },
		notify() {},
	};
	const originalError = console.error;
	console.error = () => {};

	try {
		const command = dispatchUserCommandHandler(actor, "emergencylockdown", "on", 123, commands)
			.then(() => {
				commandCompleted = true;
			});
		await alertStarted;

		assert.equal(state.emergencyLockdown, true);
		assert.deepEqual(regularEvents, [{
			event: "kick",
			payload: { reason: "Emergency server lockdown" },
		}]);
		assert.equal(regularDisconnects, 1);
		assert.equal(ownerDisconnects, 0);
		assert.equal(alertAborted, false);
		assert.equal(commandCompleted, false);

		timer.advanceTo(timeoutMs);
		await command;

		assert.equal(alertAborted, true);
		assert.equal(commandCompleted, true);
		assert.equal(state.emergencyLockdown, true);
	} finally {
		console.error = originalError;
	}
});

test("level 7 and below cannot run any server-management command", () => {
	for (const command of SERVER_MANAGEMENT_COMMANDS) {
		for (const runlevel of [0, 4, 6, 7]) {
			assert.equal(canRunServerManagementCommand(runlevel, command), false);
		}
		assert.equal(canRunServerManagementCommand(8, command), true);
	}
});

test("only Big Owner bypasses maintenance and emergency lockdown", () => {
	assert.equal(canBypassOwnerLockdown(7), false);
	assert.equal(canBypassOwnerLockdown(8), true);
});

test("restored safety messages identify active protections without credentials", () => {
	const state = { maintenance: true, emergencyLockdown: true };
	assert.equal(
		restoredSafetyStartupMessage(state),
		"[SAFETY] RESTORED MAINTENANCE MODE AND EMERGENCY LOCKDOWN — server access remains restricted."
	);
	assert.equal(
		restoredSafetyOwnerNotice(state),
		"Safety protection restored after restart: maintenance mode and emergency lockdown are active. The server remains closed to normal users until you disable it."
	);
	assert.equal(restoredSafetyStartupMessage({}), null);
	assert.equal(restoredSafetyOwnerNotice({}), null);
});

test("restored protection login events are owner-only for every saved safety mode", () => {
	const modes = [
		{
			state: { maintenance: true, emergencyLockdown: false },
			rejection: "The server is currently in maintenance mode.",
		},
		{
			state: { maintenance: false, emergencyLockdown: true },
			rejection: "The server is in emergency lockdown.",
		},
	];

	for (const { state, rejection } of modes) {
		const normalEvents = [];
		const normalSocket = {
			emit(event, payload) {
				normalEvents.push({ event, payload });
			},
		};
		assert.equal(routeRestoredSafetyLogin(normalSocket, 0, state), false);
		assert.deepEqual(normalEvents, [
			{ event: "loginFail", payload: { reason: rejection } },
		]);
		assert.equal(normalEvents.some(({ event }) => event === "alert"), false);

		const ownerEvents = [];
		const ownerSocket = {
			emit(event, payload) {
				ownerEvents.push({ event, payload });
			},
		};
		assert.equal(routeRestoredSafetyLogin(ownerSocket, 8, state), true);
		assert.deepEqual(ownerEvents, [{
			event: "alert",
			payload: {
				title: "Alert",
				text: restoredSafetyOwnerNotice(state),
			},
		}]);
		assert.equal(ownerEvents.some(({ event }) => event === "loginFail"), false);
	}
});

test("godmode promotions send restored-protection notices only to the promoted owner", async () => {
	const modes = [
		{ maintenance: true, emergencyLockdown: false },
		{ maintenance: false, emergencyLockdown: true },
	];

	for (const persistent of [false, true]) {
		for (const state of modes) {
			const promotedEvents = [];
			const otherUserEvents = [];
			const room = {
				emit(event, payload) {
					otherUserEvents.push({ event, payload });
				},
			};
			const promotedUser = {
				runlevel: 0,
				runword: null,
				room,
				updateAdmin() {},
				applyRankIcons() {},
				notify(text) {
					promotedEvents.push({
						event: "alert",
						payload: { title: "Alert", text },
					});
				},
			};
			const persisted = [];

			await runGodmodePromotion(promotedUser, "owner-word", {
				hashWord: () => "owner-hash",
				allowedHashes: ["owner-hash"],
				isLocked: () => false,
				runlevelForHash: () => 8,
				applyRankIcons() {},
				persistRankWord: async (user, hash) => persisted.push({ user, hash }),
				getSafetyState: () => state,
				persistent,
			});

			assert.equal(promotedUser.runlevel, 8);
			assert.deepEqual(promotedEvents, [{
				event: "alert",
				payload: {
					title: "Alert",
					text: restoredSafetyOwnerNotice(state),
				},
			}]);
			assert.deepEqual(otherUserEvents, []);
			assert.equal(persisted.length, persistent ? 1 : 0);
		}
	}
});

test("rejected godmode promotions do not reveal restored protection details", async () => {
	const modes = [
		{ maintenance: true, emergencyLockdown: false },
		{ maintenance: false, emergencyLockdown: true },
	];
	const rejections = [
		{
			name: "incorrect",
			hashWord: () => "incorrect-hash",
			isLocked: () => false,
			expectedNotifications: ["Incorrect password"],
		},
		{
			name: "locked",
			hashWord: () => "owner-hash",
			isLocked: () => true,
			expectedNotifications: [],
		},
	];

	for (const persistent of [false, true]) {
		for (const state of modes) {
			for (const rejection of rejections) {
				const notifications = [];
				let safetyStateReads = 0;
				let adminUpdates = 0;
				let rankIconUpdates = 0;
				let persistenceWrites = 0;
				const user = {
					runlevel: 0,
					runword: null,
					updateAdmin() {
						adminUpdates += 1;
					},
					notify(text) {
						notifications.push(text);
					},
				};

				await runGodmodePromotion(user, "rejected-word", {
					hashWord: rejection.hashWord,
					allowedHashes: ["owner-hash"],
					isLocked: rejection.isLocked,
					runlevelForHash: () => 8,
					applyRankIcons() {
						rankIconUpdates += 1;
					},
					async persistRankWord() {
						persistenceWrites += 1;
					},
					getSafetyState() {
						safetyStateReads += 1;
						return state;
					},
					persistent,
				});

				assert.deepEqual(
					notifications,
					rejection.expectedNotifications,
					`${persistent ? "pgodmode" : "godmode"} ${rejection.name} rejection`,
				);
				assert.equal(safetyStateReads, 0);
				assert.equal(adminUpdates, 0);
				assert.equal(rankIconUpdates, 0);
				assert.equal(persistenceWrites, 0);
				assert.equal(user.runlevel, 0);
				assert.equal(user.runword, null);
			}
		}
	}
});

test("godmode command dispatch preserves rejection privacy for incorrect and locked godwords", async () => {
	const safetyDetails = ["maintenance mode", "emergency lockdown", "Safety protection restored"];

	for (const command of ["godmode", "pgodmode"]) {
		for (const rejection of [
			{
				name: "incorrect",
				hashWord: () => "incorrect-hash",
				isLocked: () => false,
				expectedNotifications: ["Incorrect password"],
			},
			{
				name: "locked",
				hashWord: () => "owner-hash",
				isLocked: () => true,
				expectedNotifications: [],
			},
		]) {
			const notifications = [];
			let safetyStateReads = 0;
			let persistenceWrites = 0;
			const user = {
				runlevel: 0,
				runword: null,
				updateAdmin() {
					assert.fail(`${command} ${rejection.name} must not update admin state`);
				},
				notify(text) {
					notifications.push(text);
				},
			};
			const commands = createGodmodeCommandHandlers({
				hashWord: rejection.hashWord,
				allowedHashes: ["owner-hash"],
				isLocked: rejection.isLocked,
				runlevelForHash: () => 8,
				applyRankIcons() {
					assert.fail(`${command} ${rejection.name} must not update rank icons`);
				},
				async persistRankWord() {
					persistenceWrites += 1;
				},
				getSafetyState() {
					safetyStateReads += 1;
					return { maintenance: true, emergencyLockdown: true };
				},
			});

			await dispatchUserCommandHandler(user, command, "rejected-word", 123, commands);

			assert.deepEqual(notifications, rejection.expectedNotifications);
			assert.equal(safetyStateReads, 0);
			assert.equal(persistenceWrites, 0);
			assert.equal(user.runlevel, 0);
			assert.equal(user.runword, null);
			for (const detail of safetyDetails) {
				assert.equal(
					notifications.some((notification) => notification.includes(detail)),
					false,
					`${command} ${rejection.name} leaked ${detail}`,
				);
			}
		}
	}
});

test("successful godmode command dispatch preserves transient and persistent promotion behavior", async () => {
	const state = { maintenance: true, emergencyLockdown: true };

	for (const command of ["godmode", "pgodmode"]) {
		const notifications = [];
		const persistenceWrites = [];
		let adminUpdates = 0;
		let rankIconUpdates = 0;
		let safetyStateReads = 0;
		const user = {
			runlevel: 0,
			runword: null,
			updateAdmin() {
				adminUpdates += 1;
			},
			notify(text) {
				notifications.push(text);
			},
		};
		const commands = createGodmodeCommandHandlers({
			hashWord: word => {
				assert.equal(word, "valid-owner-word");
				return "owner-hash";
			},
			allowedHashes: ["owner-hash"],
			isLocked: () => false,
			runlevelForHash: () => 8,
			applyRankIcons(promotedUser) {
				assert.equal(promotedUser, user);
				rankIconUpdates += 1;
			},
			async persistRankWord(promotedUser, hash) {
				persistenceWrites.push({ user: promotedUser, hash });
			},
			getSafetyState() {
				safetyStateReads += 1;
				return state;
			},
		});

		await dispatchUserCommandHandler(user, command, "valid-owner-word", 123, commands);

		assert.equal(user.runlevel, 8);
		assert.equal(user.runword, "owner-hash");
		assert.equal(adminUpdates, 1);
		assert.equal(rankIconUpdates, 1);
		assert.equal(safetyStateReads, 1);
		assert.deepEqual(notifications, [restoredSafetyOwnerNotice(state)]);
		assert.deepEqual(
			persistenceWrites,
			command === "pgodmode" ? [{ user, hash: "owner-hash" }] : [],
		);
	}
});

test("pgodmode command dispatch leaves rank unchanged when persistence fails", async () => {
	const suppliedWord = "valid-owner-word-that-must-stay-private";
	const suppliedHash = "owner-hash-that-must-stay-private";
	const notifications = [];
	const socketEvents = [];
	const diagnostics = [];
	let adminUpdates = 0;
	let rankIconUpdates = 0;
	let safetyStateReads = 0;
	const user = {
		runlevel: 2,
		runword: "existing-rank-hash",
		socket: {
			emit(event, payload) {
				socketEvents.push({ event, payload });
			},
		},
		updateAdmin() {
			adminUpdates += 1;
		},
		notify(text) {
			notifications.push(text);
		},
	};
	const commands = createGodmodeCommandHandlers({
		hashWord: word => {
			assert.equal(word, suppliedWord);
			return suppliedHash;
		},
		allowedHashes: [suppliedHash],
		isLocked: () => false,
		runlevelForHash: () => 8,
		applyRankIcons() {
			rankIconUpdates += 1;
		},
		async persistRankWord(promotedUser, hash) {
			assert.equal(promotedUser, user);
			assert.equal(hash, suppliedHash);
			throw new Error(`database rejected ${suppliedWord} (${suppliedHash})`);
		},
		reportPersistenceFailure(context) {
			diagnostics.push(context);
		},
		getSafetyState() {
			safetyStateReads += 1;
			return { maintenance: true, emergencyLockdown: true };
		},
	});

	await dispatchUserCommandHandler(user, "pgodmode", suppliedWord, 123, commands);

	assert.equal(user.runlevel, 2);
	assert.equal(user.runword, "existing-rank-hash");
	assert.equal(adminUpdates, 0);
	assert.equal(rankIconUpdates, 0);
	assert.equal(safetyStateReads, 0);
	assert.deepEqual(notifications, [
		"Permanent promotion failed. Your rank was not changed.",
	]);
	assert.deepEqual(socketEvents, []);
	assert.deepEqual(diagnostics, [{
		component: "ownerSafety",
		operation: "persistPermanentRank",
		command: "pgodmode",
	}]);
	const serializedDiagnostics = JSON.stringify(diagnostics);
	assert.equal(
		notifications.some(notification => notification.includes(suppliedWord)),
		false,
	);
	assert.equal(serializedDiagnostics.includes(suppliedWord), false);
	assert.equal(serializedDiagnostics.includes(suppliedHash), false);
});

test("permanent promotion failures alert at threshold and remain rate limited", async () => {
	let currentTime = 0;
	const diagnostics = [];
	const alerts = [];
	const reportFailure = createPermanentPromotionFailureReporter({
		threshold: 3,
		windowMs: 1_000,
		cooldownMs: 5_000,
		now: () => currentTime,
		reportDiagnostic: diagnostic => diagnostics.push(diagnostic),
		reportAlert: alert => alerts.push(alert),
	});

	await reportFailure();
	currentTime = 100;
	await reportFailure();
	assert.deepEqual(alerts, []);

	currentTime = 200;
	await reportFailure();
	assert.equal(alerts.length, 1);
	assert.deepEqual(alerts[0], {
		component: "ownerSafety",
		operation: "persistPermanentRank",
		failureCount: 3,
		threshold: 3,
		windowMs: 1_000,
		cooldownMs: 5_000,
	});

	currentTime = 300;
	await reportFailure();
	currentTime = 4_999;
	await reportFailure();
	assert.equal(alerts.length, 1);

	currentTime = 5_200;
	await reportFailure();
	assert.equal(alerts.length, 1, "expired failures must not count toward a new alert");
	currentTime = 5_300;
	await reportFailure();
	currentTime = 5_400;
	await reportFailure();
	assert.equal(alerts.length, 2);
	assert.equal(diagnostics.length, 8);
});

test("shared cooldown read failures do not prevent server startup", async () => {
	const privateError = "private storage credential detail";
	const diagnostics = [];
	const reportDiagnostic = createCooldownStorageDiagnosticReporter({
		now: () => 100,
		report: context => diagnostics.push(context),
	});
	const restored = await restorePermanentPromotionAlertCooldown({
		async loadCooldown() {
			throw new Error(privateError);
		},
		reportDiagnostic,
	});

	assert.equal(restored, null);
	assert.deepEqual(diagnostics, [{
		component: "cooldownCoordination",
		operation: "load",
	}]);
	assert.equal(JSON.stringify(diagnostics).includes(privateError), false);
});

test("cooldown coordination health exposes only a recent safe stage and timestamp", () => {
	let currentTime = 100;
	const health = createCooldownCoordinationHealth({
		healthyIntervalMs: 1_000,
		now: () => currentTime,
	});
	const diagnostics = createCooldownStorageDiagnosticReporter({
		intervalMs: 10_000,
		now: () => currentTime,
		recordFailure: health.recordFailure,
	});

	diagnostics("load");
	assert.deepEqual(health.getStatus(), { failedAt: 100, stage: "load" });
	currentTime = 200;
	diagnostics("private-storage-detail");
	assert.deepEqual(health.getStatus(), { failedAt: 200, stage: "save" });
	assert.deepEqual(Object.keys(health.getStatus()).sort(), ["failedAt", "stage"]);

	health.recordSuccess();
	assert.equal(health.getStatus(), null);

	diagnostics("cleanup");
	currentTime = 1_300;
	assert.equal(health.getStatus(), null);
});

test("cooldown coordination degradation notices connected Big Owners once per episode", () => {
	let currentTime = Date.parse("2026-09-06T12:00:00.000Z");
	const ownerEvents = [];
	const secondOwnerEvents = [];
	const regularEvents = [];
	const users = [
		{ runlevel: 8, socket: { emit: (event, payload) => ownerEvents.push({ event, payload }) } },
		{ runlevel: 9, socket: { emit: (event, payload) => secondOwnerEvents.push({ event, payload }) } },
		{ runlevel: 7, socket: { emit: (event, payload) => regularEvents.push({ event, payload }) } },
	];
	const health = createCooldownCoordinationHealth({
		healthyIntervalMs: 1_000,
		now: () => currentTime,
		onDegraded: failure =>
			notifyBigOwnersOfCooldownCoordinationFailure(users, failure),
	});

	health.recordFailure("load");
	currentTime += 100;
	health.recordFailure("cleanup");

	const expected = [{
		event: "alert",
		payload: {
			title: "Cooldown coordination degraded",
			text: "Alert cooldown coordination degraded at 2026-09-06T12:00:00.000Z (load).",
		},
	}];
	assert.deepEqual(ownerEvents, expected);
	assert.deepEqual(secondOwnerEvents, expected);
	assert.deepEqual(regularEvents, []);

	health.recordSuccess();
	currentTime += 100;
	health.recordFailure("save");
	assert.equal(ownerEvents.length, 2);
	assert.match(ownerEvents[1].payload.text, /\(save\)\.$/);
});

test("a throwing Big Owner socket cannot block later cooldown degradation notices", () => {
	const ownerEvents = [];
	const lowerRankEvents = [];
	const health = createLiveCooldownCoordinationHealth({
		now: () => Date.parse("2026-09-06T12:00:00.000Z"),
		listUsers: () => [
			{
				runlevel: 8,
				socket: {
					emit() {
						throw new Error("stale socket");
					},
				},
			},
			{
				runlevel: 9,
				socket: {
					emit: (event, payload) => ownerEvents.push({ event, payload }),
				},
			},
			{
				runlevel: 7,
				socket: {
					emit: (event, payload) => lowerRankEvents.push({ event, payload }),
				},
			},
		],
	});
	const reportFailure = createCooldownStorageDiagnosticReporter({
		recordFailure: health.recordFailure,
	});

	assert.doesNotThrow(() => reportFailure("load"));
	assert.deepEqual(ownerEvents, [{
		event: "alert",
		payload: {
			title: "Cooldown coordination degraded",
			text: "Alert cooldown coordination degraded at 2026-09-06T12:00:00.000Z (load).",
		},
	}]);
	assert.deepEqual(lowerRankEvents, []);
});

test("live cooldown failure wiring alerts only connected Big Owners with safe deduplicated payloads", () => {
	let currentTime = Date.parse("2026-09-06T12:00:00.000Z");
	const events = new Map();
	const user = (id, runlevel) => ({
		runlevel,
		socket: {
			emit(event, payload) {
				const received = events.get(id) || [];
				received.push({ event, payload });
				events.set(id, received);
			},
		},
	});
	const firstOwner = user("first-owner", 8);
	const secondOwner = user("second-owner", 9);
	const lowerRank = user("lower-rank", 7);
	const rooms = new Map([
		["lobby", { users: [firstOwner, lowerRank] }],
["side-room", {
users: [
{ runlevel: 8, socket: firstOwner.socket },
secondOwner,
lowerRank,
],
}],
	]);
	const listUsers = () => [...rooms.values()].flatMap(room => room.users);
	const health = createLiveCooldownCoordinationHealth({
		healthyIntervalMs: 1_000,
		now: () => currentTime,
		listUsers,
	});
	const reportFailure = createCooldownStorageDiagnosticReporter({
		now: () => currentTime,
		recordFailure: health.recordFailure,
	});

	reportFailure("load");
	currentTime += 100;
	reportFailure("cleanup");

	const expectedLoadAlert = [{
		event: "alert",
		payload: {
			title: "Cooldown coordination degraded",
			text: "Alert cooldown coordination degraded at 2026-09-06T12:00:00.000Z (load).",
		},
	}];
	assert.deepEqual(events.get("first-owner"), expectedLoadAlert);
	assert.deepEqual(events.get("second-owner"), expectedLoadAlert);
	assert.equal(events.has("lower-rank"), false);

	rooms.get("side-room").users = [];
	health.recordSuccess();
	currentTime += 100;
	reportFailure("save");

	assert.equal(events.get("first-owner").length, 2);
	assert.deepEqual(events.get("first-owner")[1], {
		event: "alert",
		payload: {
			title: "Cooldown coordination degraded",
			text: "Alert cooldown coordination degraded at 2026-09-06T12:00:00.200Z (save).",
		},
	});
	assert.equal(events.get("second-owner").length, 1);
	assert.equal(events.has("lower-rank"), false);

	for (const ownerEvent of events.get("first-owner")) {
		assert.deepEqual(Object.keys(ownerEvent.payload).sort(), ["text", "title"]);
		assert.match(
			ownerEvent.payload.text,
			/^Alert cooldown coordination degraded at \d{4}-\d{2}-\d{2}T[\d:.]+Z \((?:load|save|cleanup)\)\.$/,
		);
	}
});

test("cooldown owner notices expose no error details and sanitize their bounded fields", () => {
	const events = [];
	const privateValues = [
		"private storage credential",
		"https://storage.example.test/private",
		"stored-user-content",
	];

	notifyBigOwnersOfCooldownCoordinationFailure([
		{ runlevel: 8, socket: { emit: (event, payload) => events.push({ event, payload }) } },
	], {
		failedAt: Number.NaN,
		stage: privateValues.join(" "),
		error: new Error(privateValues.join(" ")),
	});

	assert.equal(events.length, 1);
	assert.match(events[0].payload.text, /\(save\)\.$/);
	for (const privateValue of privateValues) {
		assert.equal(JSON.stringify(events).includes(privateValue), false);
	}
	assert.deepEqual(Object.keys(events[0].payload).sort(), ["text", "title"]);
});

test("successful cooldown restoration clears degraded coordination health", async () => {
	const health = createCooldownCoordinationHealth({ now: () => 100 });
	health.recordFailure("load");

	const restored = await restorePermanentPromotionAlertCooldown({
		loadCooldown: async () => null,
		reportSuccess: health.recordSuccess,
	});

	assert.equal(restored, null);
	assert.equal(health.getStatus(), null);
});

test("cooldown coordination health is shared, sanitized, and expires consistently", async () => {
	const file = createGenerationFile();
	await saveSharedCooldownCoordinationHealth({
		failedAt: 100,
		stage: "private-storage-detail",
		error: new Error("private credential"),
	}, { file });

	assert.deepEqual(file.read(), { failedAt: 100, stage: "save" });
	assert.deepEqual(
		await loadSharedCooldownCoordinationHealth({
			healthyIntervalMs: 1_000,
			now: 1_099,
			file,
		}),
		{ failedAt: 100, stage: "save" },
	);
	assert.equal(
		await loadSharedCooldownCoordinationHealth({
			healthyIntervalMs: 1_000,
			now: 1_100,
			file,
		}),
		null,
	);
	assert.equal(file.read(), null);
});

test("shared cooldown health keeps newer failures and successful coordination clears only older state", async () => {
	const file = createGenerationFile();
	await saveSharedCooldownCoordinationHealth({ failedAt: 200, stage: "cleanup" }, { file });
	await saveSharedCooldownCoordinationHealth({ failedAt: 100, stage: "load" }, { file });
	assert.deepEqual(file.read(), { failedAt: 200, stage: "cleanup" });

	await clearSharedCooldownCoordinationHealth({ succeededAt: 199, file });
	assert.deepEqual(file.read(), { failedAt: 200, stage: "cleanup" });
	await clearSharedCooldownCoordinationHealth({ succeededAt: 200, file });
	assert.equal(file.read(), null);
});

test("shared cooldown health retries when content changes after reading its generation", async () => {
	let generation = 1;
	let body = JSON.stringify({ failedAt: 100, stage: "load" });
	let replaced = false;
	const file = {
		async getMetadata() {
			return [{ generation: String(generation) }];
		},
		async download({ preconditionOpts }) {
			if (!replaced) {
				generation += 1;
				body = JSON.stringify({ failedAt: 200, stage: "cleanup" });
				replaced = true;
			}
			if (Number(preconditionOpts.ifGenerationMatch) !== generation) {
				throw Object.assign(new Error("changed"), { code: 412 });
			}
			return [Buffer.from(body)];
		},
	};

	assert.deepEqual(await loadSharedCooldownCoordinationHealth({
		healthyIntervalMs: 1_000,
		now: 300,
		file,
	}), { failedAt: 200, stage: "cleanup" });
});

test("sustained cooldown health read churn preserves bounded local operational status", async () => {
	let metadataReads = 0;
	let downloads = 0;
	const privateStorageDetail = "private object generation and credential detail";
	const file = {
		async getMetadata() {
			metadataReads += 1;
			return [{ generation: String(metadataReads) }];
		},
		async download() {
			downloads += 1;
			throw Object.assign(new Error(privateStorageDetail), { code: 412 });
		},
	};
	const alerts = [];
	const health = createCooldownCoordinationHealth({
		now: () => 200,
		loadShared: options => loadSharedCooldownCoordinationHealth({
			...options,
			file,
		}),
		onDegraded: failure => alerts.push(failure),
	});
	await health.recordFailure("cleanup");

	const status = await health.getSharedStatus();

	assert.deepEqual(status, { failedAt: 200, stage: "cleanup" });
	assert.deepEqual(alerts, [{ failedAt: 200, stage: "cleanup" }]);
	assert.equal(metadataReads, 3);
	assert.equal(downloads, 3);
	assert.equal(JSON.stringify(status).includes(privateStorageDetail), false);
});

test("sustained cooldown health write churn cannot suppress local failure alerts", async () => {
	let metadataReads = 0;
	let saves = 0;
	const privateStorageDetail = "private health object path";
	const file = {
		async getMetadata() {
			metadataReads += 1;
			return [{ generation: String(metadataReads) }];
		},
		async download({ preconditionOpts }) {
			return [Buffer.from(JSON.stringify({
				failedAt: 100,
				stage: "load",
			}))];
		},
		async save() {
			saves += 1;
			throw Object.assign(new Error(privateStorageDetail), { code: 412 });
		},
	};
	const ownerEvents = [];
	const health = createLiveCooldownCoordinationHealth({
		now: () => 200,
		listUsers: () => [{
			runlevel: 8,
			socket: {
				emit: (event, payload) => ownerEvents.push({ event, payload }),
			},
		}],
		saveShared: failure => saveSharedCooldownCoordinationHealth(failure, { file }),
	});

	await health.recordFailure("save");

	assert.deepEqual(health.getStatus(), { failedAt: 200, stage: "save" });
	assert.equal(metadataReads, 3);
	assert.equal(saves, 3);
	assert.equal(ownerEvents.length, 1);
	assert.deepEqual(Object.keys(ownerEvents[0].payload).sort(), ["text", "title"]);
	assert.equal(JSON.stringify(ownerEvents).includes(privateStorageDetail), false);
});

test("shared cooldown status accepts only sanitized health fields and cannot replace newer local failure", async () => {
	const privateStorageDetail = "private bucket detail";
	const health = createCooldownCoordinationHealth({
		now: () => 300,
		loadShared: async () => ({
			failedAt: 100,
			stage: "load",
			error: privateStorageDetail,
		}),
	});
	health.recordFailure("cleanup");

	const status = await health.getSharedStatus();

	assert.deepEqual(status, { failedAt: 300, stage: "cleanup" });
	assert.deepEqual(Object.keys(status).sort(), ["failedAt", "stage"]);
	assert.equal(JSON.stringify(status).includes(privateStorageDetail), false);
});

test("overlapping shared cooldown reads keep the newest request result when reads finish in reverse order", async () => {
	const pendingReads = [];
	const health = createCooldownCoordinationHealth({
		now: () => 300,
		loadShared: () => new Promise(resolve => pendingReads.push(resolve)),
	});

	const olderRead = health.getSharedStatus();
	const newerRead = health.getSharedStatus();
	await Promise.resolve();

	pendingReads[1]({
		failedAt: 250,
		stage: "cleanup",
		privateDetail: "newer private storage detail",
	});
	assert.deepEqual(await newerRead, { failedAt: 250, stage: "cleanup" });

	pendingReads[0](null);
	assert.deepEqual(await olderRead, { failedAt: 250, stage: "cleanup" });
	assert.deepEqual(health.getStatus(), { failedAt: 250, stage: "cleanup" });
	assert.deepEqual(Object.keys(health.getStatus()).sort(), ["failedAt", "stage"]);
});

test("a stale healthy shared result cannot clear a local failure recorded while it is loading", async () => {
	let finishSharedRead;
	let currentTime = 100;
	const health = createCooldownCoordinationHealth({
		now: () => currentTime,
		loadShared: () => new Promise(resolve => {
			finishSharedRead = resolve;
		}),
	});

	const sharedRead = health.getSharedStatus();
	await Promise.resolve();
	currentTime = 200;
	health.recordFailure("save");
	finishSharedRead(null);

	const status = await sharedRead;
	assert.deepEqual(status, { failedAt: 200, stage: "save" });
	assert.deepEqual(Object.keys(status).sort(), ["failedAt", "stage"]);
});

test("an older shared failure cannot undo a local recovery completed while it is loading", async () => {
	let finishSharedRead;
	let currentTime = 100;
	const privateStorageDetail = "private shared storage detail";
	const health = createCooldownCoordinationHealth({
		now: () => currentTime,
		loadShared: () => new Promise(resolve => {
			finishSharedRead = resolve;
		}),
	});

	const sharedRead = health.getSharedStatus();
	await Promise.resolve();
	currentTime = 200;
	health.recordFailure("save");
	currentTime = 300;
	health.recordSuccess();
	finishSharedRead({
		failedAt: 100,
		stage: "load",
		error: privateStorageDetail,
	});

	const status = await sharedRead;
	assert.equal(status, null);
	assert.equal(health.getStatus(), null);
	assert.equal(JSON.stringify(status).includes(privateStorageDetail), false);
});

test("separate replicas converge on the newest cooldown health across overlapping updates and expiry", async (t) => {
	const sharedObject = createGenerationAwareSharedObject();
	const workers = [0, 1, 2].map(() => fork(
		new URL("./test-fixtures/cooldownHealthWorker.js", import.meta.url),
		[],
		{ stdio: ["ignore", "ignore", "inherit", "ipc"] },
	));
	t.after(() => workers.forEach(worker => worker.kill()));

	for (const worker of workers) {
		attachSharedObjectStorage(worker, sharedObject);
	}

	const run = async (worker, command) => {
		const message = await runWorkerCommand(
			worker,
			`cooldown health ${command.operation}`,
			command,
		);
		return message.result;
	};

	await Promise.all([
		run(workers[0], {
			operation: "save",
			health: { failedAt: 100, stage: "load" },
		}),
		run(workers[1], {
			operation: "clear",
			succeededAt: 150,
		}),
		run(workers[2], {
			operation: "save",
			health: { failedAt: 200, stage: "cleanup" },
		}),
	]);

	const activeReads = await Promise.all(workers.map(worker => run(worker, {
		operation: "load",
		healthyIntervalMs: 1_000,
		now: 1_199,
	})));
	assert.deepEqual(activeReads, workers.map(() => ({
		failedAt: 200,
		stage: "cleanup",
	})));

	await run(workers[0], {
		operation: "clear",
		succeededAt: 199,
	});
	assert.deepEqual(sharedObject.read(), { failedAt: 200, stage: "cleanup" });

	const expiredReads = await Promise.all(workers.map(worker => run(worker, {
		operation: "load",
		healthyIntervalMs: 1_000,
		now: 1_200,
	})));
	assert.deepEqual(expiredReads, workers.map(() => null));
	assert.equal(sharedObject.read(), null);
});

test("replicas read the same shared cooldown health without exposing storage failures", async () => {
	const shared = { failedAt: 100, stage: "load" };
	const first = createCooldownCoordinationHealth({
		now: () => 200,
		loadShared: async () => shared,
	});
	const second = createCooldownCoordinationHealth({
		now: () => 200,
		loadShared: async () => shared,
	});
	assert.deepEqual(await first.getSharedStatus(), shared);
	assert.deepEqual(await second.getSharedStatus(), shared);

	const isolated = createCooldownCoordinationHealth({
		now: () => 200,
		loadShared: async () => {
			throw new Error("private storage credential");
		},
	});
	assert.equal(await isolated.getSharedStatus(), null);
});

test("shared cooldown health reads return local safe status at a strict deadline", async () => {
	const timer = createManualTimer();
	let finishSharedRead;
	const privateStorageDetail = "private storage endpoint";
	const health = createCooldownCoordinationHealth({
		now: () => 200,
		sharedReadTimeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadShared: () => new Promise(resolve => {
			finishSharedRead = resolve;
		}),
	});
	health.recordFailure("cleanup");

	let completed = false;
	const statusRead = health.getSharedStatus().then(status => {
		completed = true;
		return status;
	});
	await Promise.resolve();
	await Promise.resolve();
	assert.equal(completed, false);

	timer.advanceTo(20);
	const status = await statusRead;
	assert.deepEqual(status, { failedAt: 200, stage: "cleanup" });
	assert.equal(JSON.stringify(status).includes(privateStorageDetail), false);

	finishSharedRead({ failedAt: 100, stage: privateStorageDetail });
	await Promise.resolve();
	assert.deepEqual(health.getStatus(), { failedAt: 200, stage: "cleanup" });
});

test("shared cooldown health writes and cleanup stop waiting at explicit deadlines", async () => {
	for (const run of [
		options => saveSharedCooldownCoordinationHealth(
			{ failedAt: 100, stage: "save" },
			{ ...options, file: { getMetadata: () => new Promise(() => {}) } },
		),
		options => clearSharedCooldownCoordinationHealth({
			...options,
			file: { getMetadata: () => new Promise(() => {}) },
		}),
	]) {
		const timer = createManualTimer();
		let completed = false;
		const operation = run({
			timeoutMs: 20,
			setTimeoutImpl: timer.setTimeoutImpl,
			clearTimeoutImpl: timer.clearTimeoutImpl,
		}).catch(() => {
			completed = true;
		});
		await Promise.resolve();
		await Promise.resolve();
		assert.equal(completed, false);

		timer.advanceTo(20);
		await operation;
		assert.equal(completed, true);
	}
});

test("local cooldown health and owner notices complete before shared writes", async () => {
	const deadlines = [];
	const ownerEvents = [];
	const health = createLiveCooldownCoordinationHealth({
		now: () => 100,
		sharedWriteTimeoutMs: 20,
		setTimeoutImpl(callback, delay) {
			const handle = { callback, delay };
			deadlines.push(handle);
			return handle;
		},
		clearTimeoutImpl() {},
		listUsers: () => [{
			runlevel: 8,
			socket: { emit: (event, payload) => ownerEvents.push({ event, payload }) },
		}],
		saveShared: () => new Promise(() => {}),
	});

	let completed = false;
	const persistence = health.recordFailure("save").then(() => {
		completed = true;
	});
	assert.deepEqual(health.getStatus(), { failedAt: 100, stage: "save" });
	assert.equal(ownerEvents.length, 1);
	assert.equal(completed, false);
	await Promise.resolve();
	assert.equal(deadlines.length, 1);
	assert.equal(deadlines[0].delay, 20);

	deadlines[0].callback();
	await persistence;
	assert.equal(completed, true);
});

test("late shared health writes reapply the newest local state", async () => {
	let finishOldWrite;
	const calls = [];
	const health = createCooldownCoordinationHealth({
		sharedWriteTimeoutMs: 20,
		setTimeoutImpl: () => ({ unref() {} }),
		clearTimeoutImpl() {},
		saveShared: failure => {
			calls.push({ operation: "save", failure });
			return new Promise(resolve => {
				finishOldWrite = resolve;
			});
		},
		clearShared: success => {
			calls.push({ operation: "clear", success });
		},
		now: (() => {
			let value = 100;
			return () => value++;
		})(),
	});

	void health.recordFailure("load");
	await Promise.resolve();
	await health.recordSuccess();
	assert.deepEqual(calls.map(call => call.operation), ["save", "clear"]);
	assert.equal(health.getStatus(), null);

	finishOldWrite();
	await new Promise(resolve => setImmediate(resolve));
	assert.deepEqual(calls.map(call => call.operation), ["save", "clear", "clear"]);
	assert.equal(health.getStatus(), null);
});

test("database statistics return a sanitized fallback at a strict deadline", async () => {
	const timer = createManualTimer();
	const privateDatabaseDetail = "SQLITE_BUSY at /private/database/path";
	let rejectStats;
	const statsRead = getDatabaseStatsWithinDeadline({
		timeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadStats: () => new Promise((_, reject) => {
			rejectStats = reject;
		}),
	});
	let completed = false;
	statsRead.then(() => {
		completed = true;
	});
	await Promise.resolve();
	await Promise.resolve();
	assert.equal(completed, false);

	timer.advanceTo(20);
	const stats = await statsRead;
	assert.equal(stats, null);
	assert.equal(JSON.stringify(stats).includes(privateDatabaseDetail), false);

	rejectStats(new Error(privateDatabaseDetail));
	await Promise.resolve();
});

test("database statistics clear their deadline after a successful read", async () => {
	const timer = createManualTimer();
	const stats = {
		admin_logins: 1,
		audit_events: 3,
		blocked_images: 0,
		hard_bans: 2,
		ip_blocks: 0,
		message_logs: 5,
		user_joins: 4,
	};
	assert.deepEqual(await getDatabaseStatsWithinDeadline({
		timeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadStats: async () => stats,
	}), stats);
	assert.throws(() => timer.advanceTo(20), /expected an alert deadline/);
});

test("database statistics use a bounded last-known snapshot without leaking failures", async () => {
	const snapshotStore = { current: null };
	let nowMs = 1_000;
	const knownStats = {
		admin_logins: 1,
		audit_events: 3,
		blocked_images: 0,
		hard_bans: 2,
		ip_blocks: 0,
		message_logs: 5,
		user_joins: 4,
	};
	assert.deepEqual(await getDatabaseStatsWithinDeadline({
		loadStats: async () => knownStats,
		now: () => nowMs,
		snapshotStore,
	}), knownStats);

	nowMs += 15_000;
	const privateDatabaseDetail = "SQLITE_BUSY at /private/database/path";
	const staleStats = await getDatabaseStatsWithinDeadline({
		loadStats: async () => {
			throw new Error(privateDatabaseDetail);
		},
		now: () => nowMs,
		snapshotStore,
		maxSnapshotAgeMs: 30_000,
	});
	assert.deepEqual(staleStats, {
		...knownStats,
		stale: true,
		ageMs: 15_000,
	});
	assert.equal(JSON.stringify(staleStats).includes(privateDatabaseDetail), false);

	nowMs += 15_001;
	assert.equal(await getDatabaseStatsWithinDeadline({
		loadStats: async () => {
			throw new Error(privateDatabaseDetail);
		},
		now: () => nowMs,
		snapshotStore,
		maxSnapshotAgeMs: 30_000,
	}), null);
});

test("server status dispatch keeps live safety status visible while database totals go stale", async () => {
	const snapshotStore = { current: null };
	let nowMs = 1_000;
	let databaseFailure = null;
	const privateDatabaseDetail = "SQLITE_BUSY at /private/database/path";
	const knownStats = {
		admin_logins: 1,
		audit_events: 3,
		blocked_images: 0,
		hard_bans: 2,
		ip_blocks: 0,
		message_logs: 5,
		user_joins: 4,
	};
	const alerts = [];
	const user = {
		socket: {
			emit(event, payload) {
				assert.equal(event, "alert");
				alerts.push(payload);
			},
		},
	};
	const commands = {
		serverstatus: createServerStatusCommandHandler({
			getDatabaseStats: () => getDatabaseStatsWithinDeadline({
				loadStats: async () => {
					if (databaseFailure) throw databaseFailure;
					return knownStats;
				},
				now: () => nowMs,
				snapshotStore,
				maxSnapshotAgeMs: 30_000,
			}),
			getCooldownHealth: async () => null,
			listUsers: () => [{}, {}],
			getRoomCount: () => 3,
			getSafetyState: () => ({
				maintenance: true,
				emergencyLockdown: false,
			}),
			escapeHtml: value => String(value),
			uptime: () => 42,
			memoryUsage: () => ({ rss: 64 * 1024 * 1024 }),
		}),
	};

	await dispatchUserCommandHandler(user, "serverstatus", "", 1, commands);
	assert.match(alerts.at(-1).text, /Audit entries: 3/);

	databaseFailure = new Error(privateDatabaseDetail);
	nowMs += 15_000;
	await dispatchUserCommandHandler(user, "serverstatus", "", 2, commands);
	const staleStatus = alerts.at(-1);
	assert.equal(staleStatus.title, "Live server status");
	for (const line of [
		"Uptime: 42 seconds",
		"Users: 2",
		"Rooms: 3",
		"Maintenance: ON",
		"Emergency lockdown: OFF",
		"Database statistics: last known (15 seconds old)",
		"Audit entries: 3",
		"Joins: 4",
		"Messages: 5",
	]) {
		assert.match(staleStatus.text, new RegExp(line.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	}
	assert.equal(staleStatus.text.includes(privateDatabaseDetail), false);

	nowMs += 15_001;
	await dispatchUserCommandHandler(user, "serverstatus", "", 3, commands);
	const expiredStatus = alerts.at(-1).text;
	assert.match(expiredStatus, /Database statistics: unavailable/);
	assert.match(expiredStatus, /Uptime: 42 seconds/);
	assert.match(expiredStatus, /Maintenance: ON/);
	assert.equal(expiredStatus.includes("Audit entries:"), false);
	assert.equal(expiredStatus.includes(privateDatabaseDetail), false);
});

test("server status dispatch keeps degraded cooldown coordination visible and sanitized", async () => {
	const failedAt = Date.parse("2026-09-06T12:00:00.000Z");
	const privateStorageDetail = "S3 AccessDenied for private cooldown bucket";
	const cooldownHealth = createCooldownCoordinationHealth({
		now: () => failedAt,
		saveShared: async () => {
			throw new Error(privateStorageDetail);
		},
	});
	await cooldownHealth.recordFailure("cleanup");

	const alerts = [];
	const user = {
		socket: {
			emit(event, payload) {
				assert.equal(event, "alert");
				alerts.push(payload);
			},
		},
	};
	const commands = {
		serverstatus: createServerStatusCommandHandler({
			getDatabaseStats: async () => ({
				admin_logins: 1,
				audit_events: 3,
				hard_bans: 2,
				message_logs: 5,
				user_joins: 4,
			}),
			getCooldownHealth: () => cooldownHealth.getSharedStatus(),
			listUsers: () => [{}, {}],
			getRoomCount: () => 3,
			getSafetyState: () => ({
				maintenance: true,
				emergencyLockdown: false,
			}),
			escapeHtml: value => String(value),
			uptime: () => 42,
			memoryUsage: () => ({ rss: 64 * 1024 * 1024 }),
		}),
	};

	await dispatchUserCommandHandler(user, "serverstatus", "", 1, commands);
	const status = alerts.at(-1);
	assert.equal(status.title, "Live server status");
	for (const line of [
		"Uptime: 42 seconds",
		"Users: 2",
		"Rooms: 3",
		"Maintenance: ON",
		"Emergency lockdown: OFF",
		"Alert cooldown coordination: DEGRADED since 2026-09-06T12:00:00.000Z (cleanup)",
	]) {
		assert.match(status.text, new RegExp(line.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	}
	assert.equal(status.text.includes(privateStorageDetail), false);
});

test("audit history returns a sanitized fallback at a strict deadline", async () => {
	const timer = createManualTimer();
	const privateDatabaseDetail = "SQLITE_BUSY at /private/database/path";
	let rejectHistory;
	const historyRead = getAuditEventsWithinDeadline(25, {
		timeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadEvents: () => new Promise((_, reject) => {
			rejectHistory = reject;
		}),
	});
	let completed = false;
	historyRead.then(() => {
		completed = true;
	});
	await Promise.resolve();
	await Promise.resolve();
	assert.equal(completed, false);

	timer.advanceTo(20);
	const events = await historyRead;
	assert.equal(events, null);
	assert.equal(JSON.stringify(events).includes(privateDatabaseDetail), false);

	rejectHistory(new Error(privateDatabaseDetail));
	await Promise.resolve();
});

test("audit history clears its deadline after a successful read", async () => {
	const timer = createManualTimer();
	const events = [{ action: "restart" }];
	assert.deepEqual(await getAuditEventsWithinDeadline(10, {
		timeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadEvents: async limit => {
			assert.equal(limit, 10);
			return events;
		},
	}), events);
	assert.throws(() => timer.advanceTo(20), /expected an alert deadline/);
});

test("audit center uses bounded history reads and a generic unavailable message", async () => {
	const source = await readFile(new URL("./server.js", import.meta.url), "utf8");
	assert.match(source, /db\.getAuditEventsWithinDeadline\(limit\)/);
	assert.match(source, /text:\s*"Audit history is currently unavailable\."/);
	assert.equal(source.includes("text: String(error)"), false);
});

test("a timed-out observational health read cannot suppress cooldown failure alerts", async () => {
	const timer = createManualTimer();
	const alerts = [];
	const health = createCooldownCoordinationHealth({
		now: () => 200,
		sharedReadTimeoutMs: 20,
		setTimeoutImpl: timer.setTimeoutImpl,
		clearTimeoutImpl: timer.clearTimeoutImpl,
		loadShared: () => new Promise(() => {}),
		onDegraded: failure => alerts.push(failure),
	});

	const statusRead = health.getSharedStatus();
	await Promise.resolve();
	await Promise.resolve();
	timer.advanceTo(20);
	assert.equal(await statusRead, null);

	await health.recordFailure("save");
	assert.deepEqual(alerts, [{ failedAt: 200, stage: "save" }]);
	assert.deepEqual(health.getStatus(), { failedAt: 200, stage: "save" });
});

test("shared cooldown loader distinguishes invalid, expired, and active timing state", async () => {
	const fileFor = state => ({
		download: async () => [Buffer.from(JSON.stringify(state))],
		getMetadata: async () => [{ generation: "1" }],
	});

	for (const invalidState of [
		{},
		{ lastAlertAt: "100", expiresAt: 200 },
		{ lastAlertAt: 100, expiresAt: null },
		{ lastAlertAt: 200, expiresAt: 200 },
		{ lastAlertAt: 300, expiresAt: 200 },
	]) {
		await assert.rejects(
			loadSharedPromotionAlertCooldownState({
				now: 150,
				file: fileFor(invalidState),
			}),
			error => error.cooldownOperation === "load"
				&& !error.message.includes(JSON.stringify(invalidState)),
		);
	}

	assert.equal(
		await loadSharedPromotionAlertCooldownState({
			now: 200,
			file: fileFor({ lastAlertAt: 100, expiresAt: 200 }),
		}),
		null,
	);
	assert.deepEqual(
		await loadSharedPromotionAlertCooldownState({
			now: 199,
			file: fileFor({ lastAlertAt: 100, expiresAt: 200 }),
		}),
		{ lastAlertAt: 100, expiresAt: 200 },
	);
});

test("invalid shared cooldown timing emits the bounded non-sensitive load diagnostic", async () => {
	const rawStoredContent = JSON.stringify({
		lastAlertAt: "private-invalid-timestamp",
		expiresAt: 200,
	});
	const diagnostics = [];
	const reportDiagnostic = createCooldownStorageDiagnosticReporter({
		now: () => 100,
		report: context => diagnostics.push(context),
	});

	const restored = await restorePermanentPromotionAlertCooldown({
		loadCooldown: () => loadSharedPromotionAlertCooldownState({
			now: 150,
			file: {
				download: async () => [Buffer.from(rawStoredContent)],
				getMetadata: async () => [{ generation: "1" }],
			},
		}),
		reportDiagnostic,
	});

	assert.equal(restored, null);
	assert.deepEqual(diagnostics, [{
		component: "cooldownCoordination",
		operation: "load",
	}]);
	assert.equal(JSON.stringify(diagnostics).includes(rawStoredContent), false);
	assert.equal(JSON.stringify(diagnostics).includes("private-invalid-timestamp"), false);
});

test("cooldown diagnostics are bounded, non-sensitive, and cannot block handling", async () => {
	let currentTime = 100;
	const diagnostics = [];
	const privateValues = [
		"private-rank-word",
		"private-rank-hash",
		"private-session-cookie",
		"https://alerts.example.test/private",
	];
	const reportCooldownDiagnostic = createCooldownStorageDiagnosticReporter({
		intervalMs: 1_000,
		now: () => currentTime,
		report(context) {
			diagnostics.push(context);
			throw new Error(privateValues.join(" "));
		},
	});
	const alerts = [];
	const reportFailure = createPermanentPromotionFailureReporter({
		threshold: 1,
		now: () => currentTime,
		claimCooldown: async () => {
			const error = new Error(privateValues.join(" "));
			error.cooldownOperation = "save";
			throw error;
		},
		reportCooldownDiagnostic,
		reportAlert: context => alerts.push(context),
	});

	await reportFailure();
	currentTime = 200;
	reportCooldownDiagnostic("save");
	currentTime = 1_100;
	reportCooldownDiagnostic("save");

	assert.equal(alerts.length, 1);
	assert.deepEqual(diagnostics, [
		{ component: "cooldownCoordination", operation: "save" },
		{ component: "cooldownCoordination", operation: "save" },
	]);
	const serialized = JSON.stringify(diagnostics);
	for (const privateValue of privateValues) {
		assert.equal(serialized.includes(privateValue), false);
	}
});

test("cooldown storage failures identify read, write, and cleanup stages safely", async () => {
	const privateError = new Error("private storage credential detail");

	await assert.rejects(
		claimPromotionAlertCooldown(
			{ lastAlertAt: 1_000, expiresAt: 6_000 },
			{ file: { save: async () => { throw privateError; } } },
		),
		error => error.cooldownOperation === "save"
			&& !error.message.includes(privateError.message),
	);

	await assert.rejects(
		claimPromotionAlertCooldown(
			{ lastAlertAt: 1_000, expiresAt: 6_000 },
			{
				file: {
					save: async () => { throw Object.assign(new Error("exists"), { code: 412 }); },
					download: async () => { throw privateError; },
					getMetadata: async () => [{ generation: "1" }],
				},
			},
		),
		error => error.cooldownOperation === "load"
			&& !error.message.includes(privateError.message),
	);

	await assert.rejects(
		claimPromotionAlertCooldown(
			{ lastAlertAt: 1_000, expiresAt: 6_000 },
			{
				file: {
					save: async () => { throw Object.assign(new Error("exists"), { code: 412 }); },
					download: async () => [Buffer.from(JSON.stringify({
						lastAlertAt: 0,
						expiresAt: 500,
					}))],
					getMetadata: async () => [{ generation: "1" }],
					delete: async () => { throw privateError; },
				},
			},
		),
		error => error.cooldownOperation === "cleanup"
			&& !error.message.includes(privateError.message),
	);
});

test("promotion cooldown operations fail within a deadline when storage never settles", async () => {
	const never = () => new Promise(() => {});
	const deadlineOptions = { timeoutMs: 5 };

	await assert.rejects(
		loadSharedPromotionAlertCooldownState({
			file: { download: never, getMetadata: never },
			...deadlineOptions,
		}),
		error => error.cooldownOperation === "load",
	);
	await assert.rejects(
		claimPromotionAlertCooldown(
			{ lastAlertAt: 1_000, expiresAt: 6_000 },
			{ file: { save: never }, ...deadlineOptions },
		),
		error => error.cooldownOperation === "save",
	);
	await assert.rejects(
		removePromotionAlertCooldownState({
			file: {
				download: async () => [Buffer.from(JSON.stringify({
					lastAlertAt: 1_000,
					expiresAt: 6_000,
				}))],
				getMetadata: async () => [{ generation: "4" }],
				delete: never,
			},
			...deadlineOptions,
		}),
		error => error.cooldownOperation === "cleanup",
	);
});

test("a never-settling cooldown claim cannot hold back the operational alert", async () => {
	const alerts = [];
	const diagnostics = [];
	const reportFailure = createPermanentPromotionFailureReporter({
		threshold: 1,
		now: () => 1_000,
		claimCooldown: state => claimPromotionAlertCooldown(state, {
			timeoutMs: 5,
			file: { save: () => new Promise(() => {}) },
		}),
		reportCooldownDiagnostic: stage => diagnostics.push(stage),
		reportAlert: context => alerts.push(context),
	});

	await reportFailure();

	assert.equal(alerts.length, 1);
	assert.deepEqual(diagnostics, ["save"]);
});

test("a cooldown claim completing after fallback cannot create another alert", async () => {
	let finishSave;
	let currentTime = 1_000;
	const alerts = [];
	const reportFailure = createPermanentPromotionFailureReporter({
		threshold: 1,
		cooldownMs: 5_000,
		now: () => currentTime,
		claimCooldown: state => claimPromotionAlertCooldown(state, {
			timeoutMs: 5,
			file: {
				save: () => new Promise(resolve => {
					finishSave = resolve;
				}),
			},
		}),
		reportAlert: context => alerts.push(context),
	});

	await reportFailure();
	finishSave();
	await Promise.resolve();
	currentTime = 1_001;
	await reportFailure();

	assert.equal(alerts.length, 1);
});

test("late cooldown removal cannot delete a newer generation", async () => {
	let deleteOptions;
	await removePromotionAlertCooldownState({
		file: {
			download: async () => [Buffer.from(JSON.stringify({
				lastAlertAt: 1_000,
				expiresAt: 6_000,
			}))],
			getMetadata: async () => [{ generation: "4" }],
			async delete(options) {
				deleteOptions = options;
				throw Object.assign(new Error("newer state exists"), { code: 412 });
			},
		},
	});

	assert.deepEqual(deleteOptions, {
		preconditionOpts: { ifGenerationMatch: 4 },
	});
});

test("permanent promotion alert cooldown survives a rapid reporter restart", async () => {
	let currentTime = 200;
	let persistedState;
	const firstAlerts = [];
	const firstReporter = createPermanentPromotionFailureReporter({
		threshold: 1,
		cooldownMs: 5_000,
		now: () => currentTime,
		persistCooldown: state => {
			persistedState = state;
		},
		reportAlert: alert => firstAlerts.push(alert),
	});
	await firstReporter();
	assert.equal(firstAlerts.length, 1);
	assert.deepEqual(persistedState, { lastAlertAt: 200, expiresAt: 5_200 });

	currentTime = 300;
	const restartedAlerts = [];
	const restartedReporter = createPermanentPromotionFailureReporter({
		threshold: 1,
		cooldownMs: 5_000,
		now: () => currentTime,
		initialLastAlertAt: persistedState.lastAlertAt,
		reportAlert: alert => restartedAlerts.push(alert),
	});
	await restartedReporter();
	assert.equal(restartedAlerts.length, 0);

	currentTime = 5_200;
	await restartedReporter();
	assert.equal(restartedAlerts.length, 1);
});

test("separate server processes claim one shared promotion alert", async () => {
	const sharedObject = createGenerationAwareSharedObject();
	const workers = [0, 1].map(() => fork(
		new URL("./test-fixtures/promotionCooldownWorker.js", import.meta.url),
		[],
		{ stdio: ["ignore", "ignore", "inherit", "ipc"] },
	));
	workers.forEach(worker => attachSharedObjectStorage(worker, sharedObject));

	try {
		const results = await Promise.all(workers.map(worker => runWorkerCommand(
			worker,
			"claim promotion alert cooldown",
		)));
		assert.equal(results.filter(result => result.alerted).length, 1);
	} finally {
		workers.forEach(worker => worker.kill());
	}
});

test("promotion alert cooldown storage expires and contains only aggregate timing state", async () => {
	const privateValues = [
		"private-rank-word",
		"private-rank-hash",
		"private-session-cookie",
		"private-user-guid",
		"https://alerts.example.test/credential",
	];
	const saves = [];
	await claimPromotionAlertCooldown(
		{
			lastAlertAt: 1_000,
			expiresAt: 6_000,
			word: privateValues[0],
			hash: privateValues[1],
			cookie: privateValues[2],
			user: { guid: privateValues[3] },
			destination: privateValues[4],
		},
		{
			file: {
				async save(body, options) {
					saves.push({ body, options });
				},
			},
		},
	);
	assert.equal(saves.length, 1);
	assert.deepEqual(JSON.parse(saves[0].body), {
		lastAlertAt: 1_000,
		expiresAt: 6_000,
	});
	assert.deepEqual(saves[0].options.preconditionOpts, {
		ifGenerationMatch: 0,
	});
	const serialized = JSON.stringify(saves);
	for (const privateValue of privateValues) {
		assert.equal(serialized.includes(privateValue), false);
	}
});

test("permanent promotion failure alerts cannot include credentials or user details", async () => {
	const privateValues = {
		word: "private-rank-word",
		hash: "private-rank-hash",
		cookie: "private-session-cookie",
		user: { guid: "private-user-guid", name: "private-user-name" },
		error: new Error("private database detail"),
	};
	const diagnostics = [];
	const alerts = [];
	const reportFailure = createPermanentPromotionFailureReporter({
		threshold: 1,
		now: () => 123,
		reportDiagnostic: diagnostic => diagnostics.push(diagnostic),
		reportAlert: alert => alerts.push(alert),
	});

	await reportFailure(privateValues);

	assert.equal(alerts.length, 1);
	const serializedReports = JSON.stringify({ diagnostics, alerts });
	for (const secret of [
		privateValues.word,
		privateValues.hash,
		privateValues.cookie,
		privateValues.user.guid,
		privateValues.user.name,
		privateValues.error.message,
	]) {
		assert.equal(serializedReports.includes(secret), false);
	}
	assert.deepEqual(Object.keys(alerts[0]).sort(), [
		"component",
		"cooldownMs",
		"failureCount",
		"operation",
		"threshold",
		"windowMs",
	]);
});

test("permanent promotion failure webhook contains only aggregate context", async () => {
	const requests = [];
	const privateValues = [
		"private-rank-word",
		"private-rank-hash",
		"private-session-cookie",
		"private-user-guid",
	];
	const result = await sendPermanentPromotionFailureAlert({
		failureCount: 3,
		threshold: 3,
		windowMs: 300_000,
		destination: "https://alerts.example.test/permanent-promotion",
		word: privateValues[0],
		hash: privateValues[1],
		cookie: privateValues[2],
		user: { guid: privateValues[3] },
		fetchImpl: async (url, options) => {
			requests.push({ url, options });
			return { ok: true };
		},
	});

	assert.deepEqual(result, { sent: true });
	assert.equal(requests.length, 1);
	assert.equal(requests[0].url, "https://alerts.example.test/permanent-promotion");
	const serializedRequest = JSON.stringify(requests[0]);
	for (const secret of privateValues) {
		assert.equal(serializedRequest.includes(secret), false);
	}
	assert.deepEqual(JSON.parse(requests[0].options.body), {
		content: "[SAFETY] Permanent promotion storage failed 3 times within 300000ms (alert threshold: 3).",
	});
});

test("command dispatch safely rejects cyclic and missing aliases", async () => {
	for (const testCase of [
		{
			name: "cyclic alias",
			command: "first",
			commands: { first: "second", second: "first" },
			detail: "cycle",
		},
		{
			name: "missing alias target",
			command: "first",
			commands: { first: "missing" },
			detail: "missing",
		},
	]) {
		const failures = [];
		const user = {
			socket: {
				emit(event, payload) {
					assert.equal(event, "commandFail");
					failures.push(payload);
				},
			},
		};

		await dispatchUserCommandHandler(user, testCase.command, "", 123, testCase.commands);

		assert.deepEqual(
			failures,
			[{ reason: "invalidAlias", detail: testCase.detail }],
			testCase.name,
		);
	}
});

test("command resolution preserves valid aliases and passthrough commands", async () => {
	const calls = [];
	const commands = {
		alias: "canonical",
		canonical(args, messageId) {
			calls.push({ context: this, args, messageId });
		},
		clientcommand: "passthrough",
	};
	const roomEvents = [];
	const user = {
		guid: "user-guid",
		room: {
			emit(event, payload) {
				roomEvents.push({ event, payload });
			},
		},
	};

	assert.equal(resolveUserCommandHandler("alias", commands).canonical, "canonical");
	await dispatchUserCommandHandler(user, "alias", "arguments", 456, commands);
	await dispatchUserCommandHandler(user, "clientcommand", "", 789, commands);

	assert.deepEqual(calls, [{ context: user, args: "arguments", messageId: 456 }]);
	assert.deepEqual(roomEvents, [
		{ event: "clientcommand", payload: { guid: "user-guid" } },
	]);
});

test("command table validation accepts handlers, valid aliases, and passthrough commands", () => {
	const commands = {
		canonical() {},
		alias: "canonical",
		nestedAlias: "alias",
		clientcommand: "passthrough",
	};

assert.doesNotThrow(() => validateUserCommandTable(commands, {
publicCommands: ["canonical", "clientcommand"],
publicAliases: ["alias", "nestedAlias"],
}));
});

test("command table validation accepts permissions for existing commands", () => {
	const commands = {
		publicCommand() {},
		restrictedCommand() {},
	};

	assert.doesNotThrow(() => validateUserCommandTable(commands, {
		runlevels: {
			publicCommand: 0,
			restrictedCommand: 4,
		},
	}));
});

test("command table validation accepts reviewed public handlers without numeric permissions", () => {
assert.doesNotThrow(() => validateUserCommandTable({
restrictedCommand() {},
publicCommand() {},
}, {
runlevels: { restrictedCommand: 4 },
publicCommands: ["publicCommand"],
}));
});

test("command table validation accepts reviewed public aliases without numeric permissions", () => {
assert.doesNotThrow(() => validateUserCommandTable({
restrictedCommand() {},
publicAlias: "restrictedCommand",
}, {
runlevels: { restrictedCommand: 4 },
publicAliases: ["publicAlias"],
}));
});

test("command table validation reports every command without a permission decision", () => {
assert.throws(
() => validateUserCommandTable({
restrictedCommand() {},
missingHandler() {},
missingAlias: "restrictedCommand",
}, {
runlevels: { restrictedCommand: 4 },
}),
error => {
assert.match(error.message, /^Commands have no explicit permission decision:/);
assert.match(error.message, /^missingAlias$/m);
assert.match(error.message, /^missingHandler$/m);
return true;
},
);
});

test("command table validation reports every permission without a matching command", () => {
	const commands = {
		valid() {},
	};

	assert.throws(
		() => validateUserCommandTable(commands, {
			runlevels: {
				valid: 0,
				misspelled: 2,
				removedCommand: 4,
			},
		}),
		error => {
			assert.match(error.message, /^Command permissions have no matching command:/);
			assert.match(error.message, /^misspelled$/m);
			assert.match(error.message, /^removedCommand$/m);
			return true;
		},
	);
});

test("command table validation allows explicitly reviewed non-command permissions", () => {
	assert.doesNotThrow(() => validateUserCommandTable({
		valid() {},
	}, {
		runlevels: {
			valid: 0,
			externalSetting: 4,
		},
		nonCommandRunlevels: ["externalSetting"],
	}));
});

test("command table validation rejects direct aliases with weaker permissions", () => {
	const commands = {
		restricted() {},
		publicAlias: "restricted",
	};

	assert.throws(
		() => validateUserCommandTable(commands, {
runlevels: { restricted: 4, publicAlias: 0 },
		}),
		/publicAlias: runlevel 0 is weaker than restricted at 4/,
	);
});

test("command table validation rejects every weaker alias in a multi-hop chain", () => {
	const commands = {
		restricted() {},
		staffAlias: "restricted",
		publicAlias: "staffAlias",
	};

	assert.throws(
		() => validateUserCommandTable(commands, {
			runlevels: {
				restricted: 6,
				staffAlias: 4,
publicAlias: 0,
			},
		}),
		error => {
			assert.match(error.message, /^staffAlias: runlevel 4 is weaker than restricted at 6$/m);
			assert.match(error.message, /^publicAlias: runlevel 0 is weaker than restricted at 6$/m);
			return true;
		},
	);
});

test("command table validation supports explicitly reviewed public aliases", () => {
	const commands = {
		restricted() {},
		publicAlias: "restricted",
	};

	assert.doesNotThrow(() => validateUserCommandTable(commands, {
		runlevels: { restricted: 4 },
		publicAliases: ["publicAlias"],
	}));
});

test("command table validation reports every alias affected by cycles and missing targets", () => {
	const commands = {
		first: "second",
		second: "first",
		leadingIntoCycle: "first",
		missingAlias: "notConfigured",
		valid() {},
		clientcommand: "passthrough",
	};

	assert.throws(
		() => validateUserCommandTable(commands),
		error => {
			assert.match(error.message, /^Invalid command aliases:/);
			assert.match(error.message, /^first: cycle at first$/m);
			assert.match(error.message, /^second: cycle at second$/m);
			assert.match(error.message, /^leadingIntoCycle: cycle at first$/m);
			assert.match(error.message, /^missingAlias: missing at notConfigured$/m);
			assert.doesNotMatch(error.message, /^valid:/m);
			assert.doesNotMatch(error.message, /^clientcommand:/m);
			return true;
		},
	);
});

test("lower-rank godmode promotions do not reveal restored protection details", async () => {
	const modes = [
		{ maintenance: true, emergencyLockdown: false },
		{ maintenance: false, emergencyLockdown: true },
	];

	for (const persistent of [false, true]) {
		for (const state of modes) {
			const promotedEvents = [];
			let adminUpdates = 0;
			let rankIconUpdates = 0;
			const promotedUser = {
				runlevel: 0,
				runword: null,
				updateAdmin() {
					adminUpdates += 1;
				},
				notify(text) {
					promotedEvents.push({
						event: "alert",
						payload: { title: "Alert", text },
					});
				},
			};
			const persisted = [];

			await runGodmodePromotion(promotedUser, "god-word", {
				hashWord: () => "god-hash",
				allowedHashes: ["god-hash"],
				isLocked: () => false,
				runlevelForHash: () => 7,
				applyRankIcons(user) {
					assert.equal(user, promotedUser);
					rankIconUpdates += 1;
				},
				persistRankWord: async (user, hash) => persisted.push({ user, hash }),
				getSafetyState: () => state,
				persistent,
			});

			assert.equal(promotedUser.runlevel, 7);
			assert.equal(promotedUser.runword, "god-hash");
			assert.equal(adminUpdates, 1);
			assert.equal(rankIconUpdates, 1);
			assert.deepEqual(promotedEvents, []);
			assert.deepEqual(
				persisted,
				persistent ? [{ user: promotedUser, hash: "god-hash" }] : []
			);
		}
	}
});

test("server safety modes survive a clean restart cycle", async () => {
	await setServerSafetyMode("maintenance", true);
	await setServerSafetyMode("emergency_lockdown", false);
	assert.deepEqual(await loadServerSafetyState(), {
		maintenance: true,
		emergencyLockdown: false,
	});

	await setServerSafetyMode("maintenance", false);
	assert.deepEqual(await loadServerSafetyState(), {
		maintenance: false,
		emergencyLockdown: false,
	});
});

test("persisted lockdown remains active after crash-style recovery", async () => {
	await setServerSafetyMode("maintenance", false);
	await setServerSafetyMode("emergency_lockdown", true);

	// A crash performs no shutdown cleanup. A fresh startup read must therefore
	// recover the committed protection exactly as it was last saved.
	assert.deepEqual(await loadServerSafetyState(), {
		maintenance: false,
		emergencyLockdown: true,
	});

	await setServerSafetyMode("emergency_lockdown", false);
});

test("godword command logs redact credential input", () => {
	const credential = "credential-that-must-not-be-logged";
	for (const command of ["godmode", "pgodmode"]) {
		const logged = formatCommandLog(command, credential);
		assert.equal(logged, `/${command} [REDACTED]`);
		assert.equal(logged.includes(credential), false);
	}
});

test("database reset rejects missing, expired, and incorrect confirmation tokens", () => {
	const gate = new ResetConfirmationGate({ ttlMs: 100, tokenFactory: () => "valid-token" });
	assert.deepEqual(gate.requestOrConfirm("owner", "", 1), {
		status: "issued",
		token: "valid-token",
		expiresAt: 101,
	});
	assert.equal(gate.requestOrConfirm("owner", "", 2).status, "missing");
	assert.equal(gate.requestOrConfirm("owner", "wrong-token", 3).status, "incorrect");
	assert.equal(gate.requestOrConfirm("owner", "valid-token", 101).status, "expired");
	assert.equal(gate.requestOrConfirm("owner", "valid-token", 102).status, "incorrect");
});

test("valid database reset creates a snapshot before clearing application data", async () => {
	const calls = [];
	const snapshotPath = await snapshotAndResetApplicationData({
		createSnapshot: async () => {
			calls.push("snapshot");
			return "/snapshots/before-reset.db";
		},
		resetData: async () => {
			calls.push("reset");
		},
	});
	assert.equal(snapshotPath, "/snapshots/before-reset.db");
	assert.deepEqual(calls, ["snapshot", "reset"]);
});

test("database snapshot creation stops waiting at a strict deadline and ignores late success", async () => {
	const timer = createManualTimer();
	let finishSnapshot;
	const snapshotRead = createDatabaseSnapshotWithinDeadline({
		createSnapshot: () => new Promise(resolve => {
			finishSnapshot = resolve;
		}),
		timeoutMs: 20,
		...timer,
	});

	timer.advanceTo(20);
	await assert.rejects(snapshotRead, /deadline exceeded/);
	finishSnapshot("/private/snapshots/late.db");
	await Promise.resolve();
	assert.equal(DATABASE_SNAPSHOT_TIMEOUT_MS, 15_000);
});

test("database snapshot creation returns failures and clears its deadline", async () => {
	const timer = createManualTimer();
	await assert.rejects(
		createDatabaseSnapshotWithinDeadline({
			createSnapshot: async () => {
				throw new Error("private database path: disk full");
			},
			...timer,
		}),
		/disk full/,
	);
	assert.throws(
		() => timer.advanceTo(DATABASE_SNAPSHOT_TIMEOUT_MS),
		/expected an alert deadline/,
	);
});

test("database snapshot owner command reports only a generic failure", async () => {
	const source = await readFile(new URL("./server.js", import.meta.url), "utf8");
	assert.match(source, /await db\.createDatabaseSnapshotWithinDeadline\(\)/);
	assert.match(source, /Database snapshot failed\. Please try again later\./);
	assert.doesNotMatch(source, /Database snapshot failed[^"]*\$\{/);
});

test("snapshot retention keeps the newest recovery points and protects the new snapshot", async () => {
	const snapshotDir = await mkdtemp(path.join(tmpdir(), "bonziworld-snapshots-"));
	try {
		const names = [
			"bonziworld-2026-09-01T00-00-00-000Z.db",
			"bonziworld-2026-09-02T00-00-00-000Z.db",
			"bonziworld-2026-09-03T00-00-00-000Z.db",
			"bonziworld-2026-09-04T00-00-00-000Z.db",
			"notes.txt",
		];
		await Promise.all(names.map(name => writeFile(path.join(snapshotDir, name), name)));
		const protectedSnapshotPath = path.join(snapshotDir, names[0]);

		const removed = await pruneDatabaseSnapshots(snapshotDir, {
			retentionCount: 2,
			protectedSnapshotPath,
		});

		assert.deepEqual(removed.map(file => path.basename(file)), [
			"bonziworld-2026-09-03T00-00-00-000Z.db",
			"bonziworld-2026-09-02T00-00-00-000Z.db",
		]);
		assert.deepEqual((await readdir(snapshotDir)).sort(), [
			"bonziworld-2026-09-01T00-00-00-000Z.db",
			"bonziworld-2026-09-04T00-00-00-000Z.db",
			"notes.txt",
		]);
		assert.equal(DATABASE_SNAPSHOT_RETENTION_COUNT, 10);
	} finally {
		await rm(snapshotDir, { recursive: true, force: true });
	}
});

test("failed snapshot creation leaves existing data and snapshots untouched", async () => {
	const calls = [];
	await assert.rejects(
		snapshotAndResetApplicationData({
			createSnapshot: async () => {
				calls.push("snapshot");
				throw new Error("disk full");
			},
			resetData: async () => {
				calls.push("reset");
			},
		}),
		/disk full/,
	);
	assert.deepEqual(calls, ["snapshot"]);
});

test("Admin command is available at runlevel 4", () => {
	assert.equal(settings.runlevel.admin, 4);
});

test("Spotify and room background commands use their intended ranks", () => {
assert.equal(settings.runlevel.spotify, 0);
assert.equal(settings.runlevel.bspotify, 4);
assert.equal(settings.runlevel.bimage, 3);
});

test("hardbans match either the permanent IP or browser fingerprint", async () => {
	const ip = "203.0.113.250";
	const fingerprint = "f".repeat(64);
	await removeHardBan(ip, fingerprint);
	try {
		await saveHardBan(ip, fingerprint, "test hardban");
		assert.equal((await findHardBan(ip, "0".repeat(64)))?.reason, "test hardban");
		assert.equal((await findHardBan("198.51.100.250", fingerprint))?.reason, "test hardban");
	} finally {
		await removeHardBan(ip, fingerprint);
	}
});

test("hardban list is restricted to runlevel 8 and returns saved entries", async () => {
	assert.equal(settings.runlevel.hardbanlist, 8);
	const ip = "203.0.113.249";
	const fingerprint = "e".repeat(64);
	await removeHardBan(ip, fingerprint);
	try {
		await saveHardBan(ip, fingerprint, "listed hardban");
		const hardBans = await getHardBans();
		assert.ok(hardBans.some(ban =>
			ban.ip === ip &&
			ban.fingerprint === fingerprint &&
			ban.reason === "listed hardban"
		));
	} finally {
		await removeHardBan(ip, fingerprint);
	}
});

test("equivalent IPv6 spellings normalize to the same hardban identity", () => {
	assert.equal(
		canonicalizeIp("2001:db8::1"),
		canonicalizeIp("2001:0db8:0:0:0:0:0:1"),
	);
});
