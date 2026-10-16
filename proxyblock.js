// Loads proxyblocker.txt and exposes a fast isProxy(ip) test.
//
// The file may contain bare IPs ("1.2.3.4") or CIDR ranges ("1.2.3.0/24"),
// one per line. Blank lines and "#" comments are ignored. The file is
// hot-reloaded on change so the list can be updated without a restart.
import { readFileSync, watchFile } from "node:fs";
import { fileURLToPath } from "node:url";
import { makeCidrMatcher } from "./iputil.js";

const FILE = new URL("./proxyblocker.txt", import.meta.url);
const FILE_PATH = fileURLToPath(FILE);

let matcher = () => false;
let count = 0;

export function reloadProxyList() {
	try {
		const txt = readFileSync(FILE, "utf8");
		const entries = txt
			.split(/\r?\n/)
			.map((l) => l.replace(/#.*$/, "").trim())
			.filter(Boolean);
		matcher = makeCidrMatcher(entries);
		count = entries.length;
		return count;
	} catch (e) {
		console.error("proxyblock: failed to load proxyblocker.txt:", e.message);
		return count;
	}
}

reloadProxyList();

try {
	watchFile(FILE_PATH, { interval: 5000 }, () => reloadProxyList());
} catch {
	// watching is best-effort
}

export function isProxy(ip) {
	return matcher(ip);
}

export function proxyListSize() {
	return count;
}
