// IPv4 + IPv6 aware CIDR utilities.
// Everything is normalised to a BigInt so v4 and v6 share one code path.

function parseIpv6(str) {
	let s = str.split("%")[0]; // strip zone id
	if (s.indexOf("::") !== s.lastIndexOf("::")) return null; // at most one "::"
	let groups;
	if (s.includes("::")) {
		const [l, r] = s.split("::");
		const left = l ? l.split(":") : [];
		const right = r ? r.split(":") : [];
		const missing = 8 - (left.length + right.length);
		if (missing < 0) return null;
		groups = [...left, ...Array(missing).fill("0"), ...right];
	} else {
		groups = s.split(":");
	}
	if (groups.length !== 8) return null;
	let value = 0n;
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		value = (value << 16n) | BigInt(parseInt(g, 16));
	}
	return value;
}

// Returns { version: 4|6, value: BigInt } or null.
export function parseIp(ip) {
	if (typeof ip !== "string") return null;
	let s = ip.trim();
	if (!s) return null;
	// IPv4-mapped IPv6 (::ffff:1.2.3.4) -> treat as IPv4
	if (/^::ffff:/i.test(s) && s.includes(".")) s = s.slice(s.lastIndexOf(":") + 1);
	if (s.includes(".") && !s.includes(":")) {
		const parts = s.split(".");
		if (parts.length !== 4) return null;
		let v = 0n;
		for (const p of parts) {
			if (!/^\d{1,3}$/.test(p)) return null;
			const n = Number(p);
			if (n > 255) return null;
			v = (v << 8n) | BigInt(n);
		}
		return { version: 4, value: v };
	}
	if (s.includes(":")) {
		const value = parseIpv6(s);
		return value === null ? null : { version: 6, value };
	}
	return null;
}

export function canonicalizeIp(ip) {
	const parsed = parseIp(ip);
	if (!parsed) return null;
	if (parsed.version === 4) {
		return [24n, 16n, 8n, 0n]
			.map(shift => Number((parsed.value >> shift) & 255n))
			.join(".");
	}
	const groups = [];
	for (let shift = 112n; shift >= 0n; shift -= 16n) {
		groups.push(((parsed.value >> shift) & 65535n).toString(16).padStart(4, "0"));
	}
	return groups.join(":");
}

// "1.2.3.0/24" or bare "1.2.3.4" -> { version, start, end } (BigInt) or null.
export function parseCidr(cidr) {
	if (typeof cidr !== "string") return null;
	const [addr, bitsStr] = cidr.trim().split("/");
	const ip = parseIp(addr);
	if (!ip) return null;
	const maxBits = ip.version === 4 ? 32 : 128;
	const bits = bitsStr === undefined ? maxBits : Number(bitsStr);
	if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) return null;
	const shift = BigInt(maxBits - bits);
	const base = (ip.value >> shift) << shift;
	const size = 1n << shift;
	return { version: ip.version, start: base, end: base + size - 1n };
}

// Build a fast membership test over a list of CIDRs / bare IPs.
// Ranges are sorted + merged per version so lookups are O(log n) binary search.
export function makeCidrMatcher(entries) {
	const ranges = { 4: [], 6: [] };
	for (const e of entries) {
		const r = parseCidr(e);
		if (r) ranges[r.version].push(r);
	}
	for (const v of [4, 6]) {
		ranges[v].sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
		const merged = [];
		for (const r of ranges[v]) {
			const last = merged[merged.length - 1];
			if (last && r.start <= last.end + 1n) {
				if (r.end > last.end) last.end = r.end;
			} else {
				merged.push({ start: r.start, end: r.end });
			}
		}
		ranges[v] = merged;
	}
	return function (ip) {
		const parsed = parseIp(ip);
		if (!parsed) return false;
		const arr = ranges[parsed.version];
		const val = parsed.value;
		let lo = 0, hi = arr.length - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			const r = arr[mid];
			if (val < r.start) hi = mid - 1;
			else if (val > r.end) lo = mid + 1;
			else return true;
		}
		return false;
	};
}

// Official Cloudflare edge ranges (https://www.cloudflare.com/ips/).
export const CLOUDFLARE_CIDRS = [
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
];

// Loopback + RFC1918 private space (a reverse proxy on the same host/LAN).
export const LOCAL_CIDRS = [
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
];

export const isCloudflare = makeCidrMatcher(CLOUDFLARE_CIDRS);
export const isLocal = makeCidrMatcher(LOCAL_CIDRS);
