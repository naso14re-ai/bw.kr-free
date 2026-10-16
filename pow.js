import crypto from "node:crypto";

export const PowConfig = Object.freeze({
	challengePath: "/pow/challenge",
	verifyPath: "/pow/verify",
	challengeTtlMs: 60_000,
	proofTtlMs: 2 * 60_000,
	seedBytes: 16,
	minDifficulty: 2,
	maxDifficulty: 6,
	maxLevel: 4,
});

const ephemeralSecret = crypto.randomBytes(32);

function key(secret) {
	const source = secret ? Buffer.from(String(secret)) : ephemeralSecret;
	return crypto.createHash("sha256").update("bonziworld-pow:v1\0").update(source).digest();
}

function signature(body, secret, purpose) {
	return crypto.createHmac("sha256", key(secret)).update(`${purpose}\0${body}`).digest("base64url");
}

function encode(payload, secret, purpose) {
	const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `${body}.${signature(body, secret, purpose)}`;
}

function decode(token, secret, purpose) {
	if (typeof token !== "string" || token.length > 2048) return null;
	const [body, supplied] = String(token || "").split(".");
	if (!body || !supplied) return null;
	const expected = signature(body, secret, purpose);
	const suppliedBuffer = Buffer.from(supplied);
	const expectedBuffer = Buffer.from(expected);
	if (suppliedBuffer.length !== expectedBuffer.length
		|| !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) return null;
	try {
		const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
		if (!payload || payload.exp < Date.now()) return null;
		return payload;
	} catch {
		return null;
	}
}

function ipBinding(ip, secret) {
	return crypto.createHmac("sha256", key(secret)).update(`ip\0${String(ip || "")}`).digest("base64url");
}

export function powDifficultyFor(headers, level) {
	const ua = String(headers?.["user-agent"] || "").toLowerCase();
	const suspicious = (ua.includes("node.js") || ua.includes("nodejs") || /\bnode\b/.test(ua))
		&& !ua.includes("chrom")
		&& !ua.includes("firefox");
	const normalizedLevel = Math.max(1, Math.min(Number(level) || 1, PowConfig.maxLevel));
	const difficulty = normalizedLevel >= 4 ? 4 : normalizedLevel >= 3 ? 3 : PowConfig.minDifficulty;
	return Math.max(PowConfig.minDifficulty, Math.min(difficulty + (suspicious ? 1 : 0), PowConfig.maxDifficulty));
}

export function powStagesFor(level) {
	const normalizedLevel = Math.max(1, Math.min(Number(level) || 1, PowConfig.maxLevel));
	return normalizedLevel >= 4 ? 3 : normalizedLevel >= 3 ? 2 : normalizedLevel >= 2 ? 1 : 0;
}

export function createPowChallenge({ headers, ip, level, secret, now = Date.now() }) {
	const payload = {
		seed: crypto.randomBytes(PowConfig.seedBytes).toString("hex"),
		difficulty: powDifficultyFor(headers, level),
		stages: powStagesFor(level),
		ip: ipBinding(ip, secret),
		exp: now + PowConfig.challengeTtlMs,
	};
	return {
		seed: payload.seed,
		difficulty: payload.difficulty,
		stages: payload.stages,
		challengeToken: encode(payload, secret, "challenge"),
	};
}

export function verifyPowSolution({ seed, nonce, challengeToken, ip, secret }) {
	if (typeof seed !== "string" || !/^[a-f0-9]{32}$/i.test(seed)) return null;
	if (typeof nonce !== "string" || !/^\d{1,12}$/.test(nonce)) return null;
	const challenge = decode(challengeToken, secret, "challenge");
	if (!challenge || challenge.seed !== seed || challenge.ip !== ipBinding(ip, secret)) return null;
	const hash = crypto.createHash("sha256").update(`${seed}${nonce}`).digest("hex");
	if (!hash.startsWith("0".repeat(challenge.difficulty))) return null;
	return encode({
		ip: challenge.ip,
		exp: Date.now() + PowConfig.proofTtlMs,
	}, secret, "proof");
}

export function verifyPowProof({ proof, ip, secret }) {
	const payload = decode(proof, secret, "proof");
	return Boolean(payload && payload.ip === ipBinding(ip, secret));
}