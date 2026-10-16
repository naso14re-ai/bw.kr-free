export const BAN_DURATIONS_MS = Object.freeze({
	"5m": 5 * 60_000,
	"10m": 10 * 60_000,
	"15m": 15 * 60_000,
	"30m": 30 * 60_000,
	"45m": 45 * 60_000,
	"1h": 60 * 60_000,
	"2h": 2 * 60 * 60_000,
	"3h": 3 * 60 * 60_000,
	"6h": 6 * 60 * 60_000,
	"permanent": null,
});

export const MUTE_DURATION_MS = 15 * 60_000;

export function moderationMinimumRunlevel(action, duration = "") {
	if (action === "kick") return 2;
	if (action === "ban") return duration === "permanent" ? 3 : 2;
	if (action === "mute") return 3;
	if (action === "shadowban" || action === "unshadowban") return 4;
	return Infinity;
}

export function parseModerationRequest(input) {
	const [actionRaw = "", durationRaw = "", target = "", ...reasonParts] =
		String(input || "").trim().split(/\s+/);
	const action = actionRaw.toLowerCase();
	const duration = durationRaw.toLowerCase();
	if (!["kick", "ban", "mute", "shadowban", "unshadowban"].includes(action)) return null;
	if (!target) return null;
	if (action === "ban" && !Object.hasOwn(BAN_DURATIONS_MS, duration)) return null;
	if (action === "mute" && duration !== "15m") return null;
	if (["kick", "shadowban", "unshadowban"].includes(action) && duration !== "none") return null;
	return {
		action,
		duration,
		target,
		reason: reasonParts.join(" ").trim(),
	};
}