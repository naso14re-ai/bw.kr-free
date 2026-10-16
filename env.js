import fs from "node:fs";
import path from "node:path";

export function loadServerEnv(baseDir = process.cwd()) {
	const envPath = path.join(baseDir, ".env");

	if (!fs.existsSync(envPath)) {
		return false;
	}

	const content = fs.readFileSync(envPath, "utf8");
	for (const line of content.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;
		const separator = trimmed.indexOf("=");
		if (separator === -1) continue;

		const key = trimmed.slice(0, separator).trim();
		const value = trimmed.slice(separator + 1).trim();
if (key && process.env[key] === undefined) {
process.env[key] = value;
}
	}

	return true;
}

export function restoredSafetyAlertUrl(env = process.env) {
	return alertUrl(env.RESTORED_SAFETY_ALERT_URL);
}

export function permanentPromotionAlertUrl(env = process.env) {
	return alertUrl(env.PERMANENT_PROMOTION_ALERT_URL);
}

function alertUrl(value) {
	const configured = String(value ?? "").trim();
	if (!configured) return null;

	try {
		const url = new URL(configured);
		return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
	} catch {
		return null;
	}
}
