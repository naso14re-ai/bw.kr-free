import crypto from "node:crypto";

export const SERVER_MANAGEMENT_COMMANDS = new Set([
	"restart",
	"serverstatus",
	"auditcenter",
	"maintenancemode",
	"emergencylockdown",
	"databasesnapshot",
	"resetdatabase",
	"promoteowner",
	"demoteowner",
]);

export function canRunServerManagementCommand(runlevel, command) {
	return Number(runlevel) >= 8 && SERVER_MANAGEMENT_COMMANDS.has(command);
}

export function canBypassOwnerLockdown(runlevel) {
	return Number(runlevel) >= 8;
}

export function createServerStatusCommandHandler({
	getDatabaseStats,
	getCooldownHealth,
	listUsers,
	getRoomCount,
	getSafetyState,
	escapeHtml,
	uptime = () => process.uptime(),
	memoryUsage = () => process.memoryUsage(),
} = {}) {
	return async function () {
		const memory = memoryUsage();
		const [stats, cooldownHealth] = await Promise.all([
			getDatabaseStats(),
			getCooldownHealth(),
		]);
		const safetyState = getSafetyState();
		const lines = [
			`Uptime: ${Math.floor(uptime())} seconds`,
			`Users: ${listUsers().length}`,
			`Rooms: ${getRoomCount()}`,
			`Memory RSS: ${(memory.rss / 1024 / 1024).toFixed(1)} MB`,
			`Maintenance: ${safetyState.maintenance ? "ON" : "OFF"}`,
			`Emergency lockdown: ${safetyState.emergencyLockdown ? "ON" : "OFF"}`,
			...(stats ? [
				...(stats.stale
					? [`Database statistics: last known (${Math.floor(stats.ageMs / 1000)} seconds old)`]
					: []),
				`Audit entries: ${stats.audit_events}`,
				`Joins: ${stats.user_joins}`,
				`Messages: ${stats.message_logs}`,
				`Hardbans: ${stats.hard_bans}`,
				`Persistent rank logins: ${stats.admin_logins}`,
			] : ["Database statistics: unavailable"]),
			cooldownHealth
				? `Alert cooldown coordination: DEGRADED since ${new Date(cooldownHealth.failedAt).toISOString()} (${cooldownHealth.stage})`
				: "Alert cooldown coordination: healthy",
		];
		this.socket.emit("alert", {
			title: "Live server status",
			text: lines.map(escapeHtml).join("<br>"),
		});
	};
}

export function activeSafetyModeLabels({ maintenance = false, emergencyLockdown = false } = {}) {
	const modes = [];
	if (maintenance) modes.push("maintenance mode");
	if (emergencyLockdown) modes.push("emergency lockdown");
	return modes;
}

export function restoredSafetyStartupMessage(state) {
	const modes = activeSafetyModeLabels(state);
	if (modes.length === 0) return null;
	return `[SAFETY] RESTORED ${modes.join(" and ").toUpperCase()} — server access remains restricted.`;
}

export function restoredSafetyOwnerNotice(state) {
	const modes = activeSafetyModeLabels(state);
	if (modes.length === 0) return null;
	const verb = modes.length === 1 ? "is" : "are";
	return `Safety protection restored after restart: ${modes.join(" and ")} ${verb} active. The server remains closed to normal users until you disable it.`;
}

const COOLDOWN_STORAGE_OPERATIONS = new Set(["load", "save", "cleanup"]);

function sanitizeCooldownCoordinationFailure(failure) {
	if (
		!Number.isFinite(failure?.failedAt)
		|| !COOLDOWN_STORAGE_OPERATIONS.has(failure?.stage)
	) return null;
	return {
		failedAt: failure.failedAt,
		stage: failure.stage,
	};
}

export function createCooldownCoordinationHealth({
	healthyIntervalMs = 5 * 60_000,
	sharedReadTimeoutMs = 1_000,
	sharedWriteTimeoutMs = 1_000,
	now = () => Date.now(),
	onDegraded = () => {},
	loadShared = null,
	saveShared = null,
	clearShared = null,
	setTimeoutImpl = setTimeout,
	clearTimeoutImpl = clearTimeout,
} = {}) {
	let recentFailure = null;
	let sharedRevision = 0;
	let latestSharedOperation = null;
	let statusRevision = 0;
	let sharedReadRevision = 0;

	function persistShared(operation, revision) {
		let timeoutHandle;
		let storagePromise;
		try {
			storagePromise = Promise.resolve().then(operation);
		} catch {
			return Promise.resolve();
		}
		storagePromise.then(
			() => {
				if (revision !== sharedRevision && latestSharedOperation) {
					void persistShared(latestSharedOperation, sharedRevision);
				}
			},
			() => {},
		);
		const deadline = new Promise((resolve) => {
			timeoutHandle = setTimeoutImpl(resolve, sharedWriteTimeoutMs);
			timeoutHandle?.unref?.();
		});
		return Promise.race([storagePromise.catch(() => {}), deadline]).finally(() => {
			if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
		});
	}

	return {
		recordFailure(stage) {
			const failedAt = now();
			const wasDegraded = recentFailure
				&& failedAt - recentFailure.failedAt < healthyIntervalMs;
			recentFailure = {
				failedAt,
				stage: COOLDOWN_STORAGE_OPERATIONS.has(stage) ? stage : "save",
			};
			statusRevision += 1;
			if (!wasDegraded) {
				try {
					onDegraded({ ...recentFailure });
				} catch {
					// Owner notices must never interfere with coordination diagnostics.
				}
			}
			const failure = { ...recentFailure };
			if (!saveShared) return Promise.resolve();
			const operation = () => saveShared?.(failure);
			latestSharedOperation = operation;
			return persistShared(operation, ++sharedRevision);
		},
		recordSuccess() {
			const succeededAt = now();
			recentFailure = null;
			statusRevision += 1;
			if (!clearShared) return Promise.resolve();
			const operation = () => clearShared?.({ succeededAt });
			latestSharedOperation = operation;
			return persistShared(operation, ++sharedRevision);
		},
		getStatus() {
			if (
				recentFailure
				&& now() - recentFailure.failedAt >= healthyIntervalMs
			) {
				recentFailure = null;
				statusRevision += 1;
			}
			return recentFailure ? { ...recentFailure } : null;
		},
		async getSharedStatus() {
			if (!loadShared) return this.getStatus();
			const readRevision = ++sharedReadRevision;
			const startingStatusRevision = statusRevision;
			let timeoutHandle;
			try {
				const sharedRead = Promise.resolve().then(() =>
					loadShared({ healthyIntervalMs, now: now() })
				);
				const deadline = new Promise((_, reject) => {
					timeoutHandle = setTimeoutImpl(() => reject(new Error("deadline")), sharedReadTimeoutMs);
					timeoutHandle?.unref?.();
				});
				const shared = sanitizeCooldownCoordinationFailure(
					await Promise.race([sharedRead, deadline]),
				);
				if (
					readRevision === sharedReadRevision
					&& startingStatusRevision === statusRevision
					&& (
						!recentFailure
						|| !shared
						|| shared.failedAt >= recentFailure.failedAt
					)
				) {
					recentFailure = shared;
					statusRevision += 1;
				}
			} catch {
				// Health reads are observational and must not affect coordination.
			} finally {
				if (timeoutHandle !== undefined) clearTimeoutImpl(timeoutHandle);
			}
			return this.getStatus();
		},
	};
}

export function notifyBigOwnersOfCooldownCoordinationFailure(
	users,
	{ failedAt, stage } = {},
) {
	const safeStage = COOLDOWN_STORAGE_OPERATIONS.has(stage) ? stage : "save";
	const safeFailedAt = Number.isFinite(failedAt) ? failedAt : Date.now();
	const notice = {
		title: "Cooldown coordination degraded",
		text: `Alert cooldown coordination degraded at ${new Date(safeFailedAt).toISOString()} (${safeStage}).`,
	};
	const notifiedSockets = new Set();

	for (const user of users || []) {
		if (Number(user?.runlevel) < 8) continue;
		const socket = user?.socket;
		if (!socket || notifiedSockets.has(socket)) continue;
		notifiedSockets.add(socket);
		try {
			socket.emit("alert", notice);
		} catch {
			// One disconnected owner must not prevent notices to other owners.
		}
	}
}

export function createLiveCooldownCoordinationHealth({
	listUsers,
	...healthOptions
} = {}) {
	return createCooldownCoordinationHealth({
		...healthOptions,
		onDegraded(failure) {
			notifyBigOwnersOfCooldownCoordinationFailure(listUsers?.(), failure);
		},
	});
}

export function createCooldownStorageDiagnosticReporter({
	intervalMs = 60_000,
	now = () => Date.now(),
	recordFailure = () => {},
	report = () => {},
} = {}) {
	const lastReportedAt = new Map();

	return function reportCooldownStorageFailure(operation) {
		const safeOperation = COOLDOWN_STORAGE_OPERATIONS.has(operation)
			? operation
			: "save";
		const occurredAt = now();
		try {
			Promise.resolve(recordFailure(safeOperation)).catch(() => {});
		} catch {
			// Health reporting must never interfere with cooldown coordination.
		}
		const previous = lastReportedAt.get(safeOperation);
		if (Number.isFinite(previous) && occurredAt - previous < intervalMs) return;
		lastReportedAt.set(safeOperation, occurredAt);

		try {
			Promise.resolve(report({
				component: "cooldownCoordination",
				operation: safeOperation,
			})).catch(() => {});
		} catch {
			// Diagnostics must never interfere with startup or promotion handling.
		}
	};
}

export async function restorePermanentPromotionAlertCooldown({
	loadCooldown,
	reportDiagnostic = () => {},
	reportSuccess = () => {},
}) {
	try {
		const cooldown = await loadCooldown();
		try {
			await reportSuccess();
		} catch {
			// Health reporting must never interfere with startup recovery.
		}
		return cooldown;
	} catch {
		try {
			reportDiagnostic("load");
		} catch {
			// Startup cooldown recovery must never prevent the server from starting.
		}
		return null;
	}
}

export function createPermanentPromotionFailureReporter({
	threshold = 3,
	windowMs = 5 * 60_000,
	cooldownMs = 15 * 60_000,
	now = () => Date.now(),
	initialLastAlertAt = Number.NEGATIVE_INFINITY,
	persistCooldown = () => {},
	claimCooldown,
	reportDiagnostic = () => {},
	reportCooldownDiagnostic = reportDiagnostic,
	reportAlert = () => {},
} = {}) {
	let recentFailures = [];
	let lastAlertAt = Number.isFinite(initialLastAlertAt)
		? initialLastAlertAt
		: Number.NEGATIVE_INFINITY;

	return async function reportPermanentPromotionFailure() {
		const occurredAt = now();
		recentFailures = recentFailures
			.filter(timestamp => occurredAt - timestamp < windowMs);
		recentFailures.push(occurredAt);

		const diagnostic = {
			component: "ownerSafety",
			operation: "persistPermanentRank",
			command: "pgodmode",
		};
		try {
			reportDiagnostic(diagnostic);
		} catch {
			// Diagnostics must not interfere with alerting or the safe failure path.
		}

		if (
			recentFailures.length < threshold
			|| occurredAt - lastAlertAt < cooldownMs
		) return;

		const cooldownState = {
			lastAlertAt: occurredAt,
			expiresAt: occurredAt + cooldownMs,
		};
		let claimed = true;
		try {
			if (claimCooldown) {
				claimed = await claimCooldown(cooldownState);
			} else {
				persistCooldown(cooldownState);
			}
		} catch (error) {
			try {
				reportCooldownDiagnostic(
					COOLDOWN_STORAGE_OPERATIONS.has(error?.cooldownOperation)
						? error.cooldownOperation
						: "save",
				);
			} catch {
				// Cooldown diagnostics must not interfere with operational alerting.
			}
			// Cooldown persistence must not interfere with operational alerting.
		}
		lastAlertAt = occurredAt;
		if (!claimed) return;
		try {
			reportAlert({
				component: "ownerSafety",
				operation: "persistPermanentRank",
				failureCount: recentFailures.length,
				threshold,
				windowMs,
				cooldownMs,
			});
		} catch {
			// Operational alert delivery must not interfere with promotion safety.
		}
	};
}

export async function runGodmodePromotion(user, word, {
	hashWord,
	allowedHashes,
	isLocked,
	runlevelForHash,
	applyRankIcons,
	persistRankWord,
	reportPersistenceFailure = () => {},
	getSafetyState,
	persistent = false,
}) {
	const hashed = hashWord(word);
	if (!allowedHashes.includes(hashed)) {
		user.notify("Incorrect password");
		return;
	}
	if (isLocked(hashed)) return;

	const level = runlevelForHash(hashed);
	if (level <= 0) return;

	if (persistent) {
		try {
			await persistRankWord(user, hashed);
		} catch {
			try {
				reportPersistenceFailure({
					component: "ownerSafety",
					operation: "persistPermanentRank",
					command: "pgodmode",
				});
			} catch {
				// Diagnostics must not interfere with the safe user-facing failure path.
			}
			user.notify("Permanent promotion failed. Your rank was not changed.");
			return;
		}
	}

	user.runlevel = level;
	user.runword = hashed;
	user.updateAdmin();
	applyRankIcons(user);

	if (level >= 8) {
		const notice = restoredSafetyOwnerNotice(getSafetyState());
		if (notice) user.notify(notice);
	}
}

export function createGodmodeCommandHandlers(options) {
	return {
		godmode(word) {
			return runGodmodePromotion(this, word, {
				...options,
				persistent: false,
			});
		},
		pgodmode(word) {
			return runGodmodePromotion(this, word, {
				...options,
				persistent: true,
			});
		},
	};
}

export function resolveUserCommandHandler(command, commands) {
	let canonical = command;
	const seen = new Set();

	while (true) {
		if (seen.has(canonical)) {
			return { error: "cycle", canonical };
		}
		seen.add(canonical);

		if (!Object.hasOwn(commands, canonical)) {
			return { error: "missing", canonical };
		}

		const handler = commands[canonical];
		if (handler === "passthrough") {
			return { canonical, passthrough: true };
		}
		if (typeof handler !== "string") {
			if (typeof handler !== "function") {
				return { error: "missing", canonical };
			}
			return { canonical, handler };
		}
		canonical = handler;
	}
}

export function validateUserCommandTable(commands, {
	runlevels = {},
	publicCommands = [],
	publicAliases = [],
	nonCommandRunlevels = [],
} = {}) {
	const failures = [];
	const reviewedPublicCommands = new Set(publicCommands);
	const reviewedPublicAliases = new Set(publicAliases);
	const reviewedNonCommandRunlevels = new Set(nonCommandRunlevels);

	for (const command of Object.keys(commands)) {
		const resolved = resolveUserCommandHandler(command, commands);
		if (resolved.error) {
			failures.push(`${command}: ${resolved.error} at ${resolved.canonical}`);
			continue;
		}
		if (typeof commands[command] !== "string" || resolved.passthrough) continue;

		const hasAliasPermissionDecision = Object.hasOwn(runlevels, command)
			|| reviewedPublicAliases.has(command);
		if (!hasAliasPermissionDecision) continue;

		const aliasLevel = Number(runlevels[command] ?? 0);
		const canonicalLevel = Number(runlevels[resolved.canonical] ?? 0);
		if (aliasLevel < canonicalLevel && !reviewedPublicAliases.has(command)) {
			failures.push(
				`${command}: runlevel ${aliasLevel} is weaker than ${resolved.canonical} at ${canonicalLevel}`,
			);
		}
	}

	if (failures.length > 0) {
		throw new Error(`Invalid command aliases:\n${failures.join("\n")}`);
	}

	const staleRunlevels = Object.keys(runlevels)
		.filter(command => !Object.hasOwn(commands, command))
		.filter(command => !reviewedNonCommandRunlevels.has(command))
		.sort();
	if (staleRunlevels.length > 0) {
		throw new Error(
			`Command permissions have no matching command:\n${staleRunlevels.join("\n")}`,
		);
	}

	const commandsWithoutPermissionDecisions = Object.keys(commands)
		.filter(command => !Object.hasOwn(runlevels, command))
		.filter(command => {
			const isAlias = typeof commands[command] === "string"
				&& commands[command] !== "passthrough";
			return isAlias
				? !reviewedPublicAliases.has(command)
				: !reviewedPublicCommands.has(command);
		})
		.sort();
	if (commandsWithoutPermissionDecisions.length > 0) {
		throw new Error(
			`Commands have no explicit permission decision:\n${commandsWithoutPermissionDecisions.join("\n")}`,
		);
	}
}

export async function dispatchUserCommandHandler(user, command, args, messageId, commands) {
	const resolved = resolveUserCommandHandler(command, commands);
	if (resolved.error) {
		user.socket.emit("commandFail", {
			reason: "invalidAlias",
			detail: resolved.error,
		});
		return;
	}
	if (resolved.passthrough) {
		user.room.emit(command, { guid: user.guid });
		return;
	}
	await resolved.handler.call(user, args, messageId);
}

export function routeRestoredSafetyLogin(socket, runlevel, state = {}) {
	if (activeSafetyModeLabels(state).length === 0) return true;

	if (!canBypassOwnerLockdown(runlevel)) {
		socket.emit("loginFail", {
			reason: state.emergencyLockdown
				? "The server is in emergency lockdown."
				: "The server is currently in maintenance mode.",
		});
		return false;
	}

	socket.emit("alert", {
		title: "Alert",
		text: restoredSafetyOwnerNotice(state),
	});
	return true;
}

export function formatCommandLog(command, args) {
	const normalized = String(command || "").toLowerCase();
	if (normalized === "godmode" || normalized === "pgodmode") {
		return `/${normalized} [REDACTED]`;
	}
if (normalized === "massdemote") {
return `/${normalized} ${String(args || "").replace(/(--confirm)\s+\S+/i, "$1 [REDACTED]")}`;
}
	return `/${normalized} ${String(args || "")}`;
}

export function parseMassDemoteRequest(input) {
	let value = String(input || "").trim();
	let token = "";
	const confirmation = value.match(/\s+--confirm\s+([a-f0-9]{6,64})\s*$/i);
	if (confirmation) {
		token = confirmation[1].toLowerCase();
		value = value.slice(0, confirmation.index).trim();
	}

	if (!value) return { error: "Usage: /massdemote all OR /massdemote regex <name-pattern>" };
	if (value.toLowerCase() === "all") {
		return { selector: "all", pattern: "", token };
	}

	const pattern = value.replace(/^regex\s+/i, "").trim();
	if (!pattern) return { error: "A name regex is required." };
	if (pattern.length > 80) return { error: "The name regex must be 80 characters or fewer." };
	if (/\\[1-9]|\(\?/.test(pattern)) {
		return { error: "Backreferences and lookaround are not allowed in mass-demote regexes." };
	}
	if (/(?:[+*?]|\{\d+(?:,\d*)?\})(?:[+*?]|\{\d+(?:,\d*)?\})/.test(pattern)
		|| /\([^)]*(?:[+*]|\{\d+(?:,\d*)?\})[^)]*\)(?:[+*]|\{\d+(?:,\d*)?\})/.test(pattern)) {
		return { error: "Nested or repeated regex quantifiers are not allowed." };
	}

	try {
		new RegExp(pattern, "iu");
	} catch {
		return { error: "That name regex is invalid." };
	}
	return { selector: "regex", pattern, token };
}

export function selectMassDemoteTargets(users, actor, request) {
	const matcher = request.selector === "all"
		? () => true
		: (user) => new RegExp(request.pattern, "iu").test(String(user?.public?.name || ""));

	return [...users].filter((user) =>
		user
		&& user !== actor
		&& Number(user.runlevel) < 8
		&& (Number(user.runlevel) > 0 || !!user.runword)
		&& matcher(user)
	);
}

export class ResetConfirmationGate {
	constructor({ ttlMs = 60_000, tokenFactory = () => crypto.randomBytes(6).toString("hex") } = {}) {
		this.ttlMs = ttlMs;
		this.tokenFactory = tokenFactory;
		this.pending = new Map();
	}

	requestOrConfirm(key, supplied, now = Date.now()) {
		const token = String(supplied || "").trim();
		const pending = this.pending.get(key);

		if (!pending) {
			if (token) return { status: "incorrect" };
			const issued = this.tokenFactory();
			this.pending.set(key, { token: issued, expiresAt: now + this.ttlMs });
			return { status: "issued", token: issued, expiresAt: now + this.ttlMs };
		}
		if (pending.expiresAt <= now) {
			this.pending.delete(key);
			return { status: "expired" };
		}
		if (!token) return { status: "missing" };
		if (token !== pending.token) return { status: "incorrect" };

		this.pending.delete(key);
		return { status: "confirmed" };
	}
}
