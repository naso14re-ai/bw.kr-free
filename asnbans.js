import NodeCache from "node-cache";
import * as db from "./database.js";

export const asnbans = new Set();

const asnCache = new NodeCache({
	stdTTL: 86400,
	checkperiod: 3600
});

export async function initAsnBans() {
	try {
		const active = await db.getActiveAsnBans();
		asnbans.clear();
		for (const row of active) {
			if (row.asn) asnbans.add(row.asn);
		}
	} catch (err) {}
}

export async function getAsn(ip) {
	const cachedAsn = asnCache.get(ip);
	if (cachedAsn) return cachedAsn;

	const asn = await db.getAsnFromIp(ip);
	if (asn) asnCache.set(ip, asn);
	return asn;
}

export async function isIpAsnBanned(ip) {
	const asn = await getAsn(ip);
	if (!asn) return false;
	return asnbans.has(asn);
}

export async function addAsnBan(asn, reason) {
	asnbans.add(asn);
	await db.saveAsnBan(asn, reason);
}

export async function removeAsnBan(asn) {
	asnbans.delete(asn);
	await db.removeAsnBan(asn);
}

initAsnBans();