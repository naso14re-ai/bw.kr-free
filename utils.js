import crypto from "node:crypto";

export function guidGen() {
	function s4() {
		return Math.floor((1 + Math.random()) * 0x10000)
			.toString(16)
			.substring(1);
	};

	let id = '';
	for (let i = 0; i < 4; i++)
		id += s4();
	return id;
}

export function randomInt(min, max) {
	return Math.floor(((max - min + 1) * Math.random()) + min);
};

export function sanitizeUnicode(str) {
	if (!str) return str;
	const REPLACEMENT = "\uFFFD";
	let out = "";

	for (let i = 0; i < str.length; i++) {
		const code = str.charCodeAt(i);
		
		if (code === 0) {
			out += REPLACEMENT;
			continue;
		}

		if (code >= 0xD800 && code <= 0xDBFF) {
			const next = str.charCodeAt(i + 1);
			if (!(next >= 0xDC00 && next <= 0xDFFF)) {
				out += REPLACEMENT;
			} else {
				out += str[i] + str[i + 1];
				i++;
			}
			continue;
		}

		if (code >= 0xDC00 && code <= 0xDFFF) {
			out += REPLACEMENT;
			continue;
		}

		out += str[i];
	}
	
	return out;
}

export function cookieParser(req, res, next) {
	if (!req.headers.cookie) {
		req.cookie = {};
		next();
		return;
	}
	let cookie = req.headers.cookie;
	let cookies = {};
	let keypairs = cookie.split("; ");
	for (let keypair of keypairs) {
		let equalPos = keypair.indexOf("=");
		let key = keypair.slice(0, equalPos);
		let val = decodeURIComponent(keypair.slice(equalPos + 1));
		cookies[key] = val;
	}
	req.cookie = cookies;
	next();
}

// ---------------------------------------------------------------------------
// Handshake "pass" cookie: an unforgeable proof that a client actually loaded
// the page over HTTP. Express issues it (see index.js); the socket flood guard
// requires it (see app.js). An off-site Node/eval flood script can forge the
// Origin header but cannot forge this without first fetching the site over HTTP.
//
// The HMAC key is resolved lazily: .env is loaded after this module is first
// evaluated, so resolving on first use derives the key from the real GODWORD
// (or an explicit PASS_SECRET) instead of an empty string. It's memoised so the
// key is stable for the life of the process — cookies survive between requests
// and across the whole fleet of connections.
let _passSecret = null;
function passSecret() {
	if (_passSecret) return _passSecret;
	_passSecret = process.env.PASS_SECRET
		? Buffer.from(process.env.PASS_SECRET)
		: crypto.createHash("sha256").update("bonzi-pass:" + (process.env.GODWORD || "")).digest();
	return _passSecret;
}

// Sign a token (the existing identity cookie) into a handshake proof.
export function signPass(token) {
	return crypto.createHmac("sha256", passSecret()).update(String(token)).digest("base64url");
}

// Verify the "pass" cookie in a raw cookie header matches the "token" cookie's
// signature. Wrapped in try/catch + constant-time compare so a malformed cookie
// can neither crash the handshake (a DoS vector) nor leak the key by timing.
export function checkPass(cookieHeader) {
	if (!cookieHeader) return false;
	try {
		let token, pass;
		for (const part of String(cookieHeader).split(";")) {
			const i = part.indexOf("=");
			if (i === -1) continue;
			const k = part.slice(0, i).trim();
			const v = part.slice(i + 1).trim();
			if (k === "token") token = decodeURIComponent(v);
			else if (k === "pass") pass = decodeURIComponent(v);
		}
		if (!token || !pass) return false;
		const expected = signPass(token);
		const a = Buffer.from(pass);
		const b = Buffer.from(expected);
		return a.length === b.length && crypto.timingSafeEqual(a, b);
	} catch {
		return false;
	}
}