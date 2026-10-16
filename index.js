import * as fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import os from "node:os";
import { spawn } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.resolve(__dirname, "..");
const sourceArchivePath = path.join(os.tmpdir(), `bonziworld-source-${process.pid}.zip`);
let sourceArchivePromise;

const SOURCE_EXTENSIONS = new Set([
".css", ".html", ".js", ".json", ".md", ".txt", ".xml",
]);
const SOURCE_EXCLUDED_PATHS = new Set([
"bans.json",
"client/src/community-edition",
"server/snapshots",
]);

function collectSourceFiles(directory, relativeDirectory = "") {
const files = [];
for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "build") continue;
const relativePath = path.join(relativeDirectory, entry.name);
if (SOURCE_EXCLUDED_PATHS.has(relativePath)) continue;
const absolutePath = path.join(directory, entry.name);
if (entry.isDirectory()) {
files.push(...collectSourceFiles(absolutePath, relativePath));
continue;
}
const isPublicClientAsset = relativePath.startsWith(path.join("client", "src") + path.sep);
if (isPublicClientAsset || SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
files.push(relativePath);
}
}
return files;
}

function ensureSourceArchive() {
if (sourceArchivePromise) return sourceArchivePromise;
sourceArchivePromise = new Promise((resolve, reject) => {
const files = collectSourceFiles(projectDir).sort();
// `zip` updates an existing archive without removing entries that are no
// longer in the source list. Always begin with a clean file so a reused PID or
// hot restart cannot leave hundreds of stale files in the download.
fs.rmSync(sourceArchivePath, { force: true });
const zip = spawn("zip", ["-q", sourceArchivePath, "-@"], {
cwd: projectDir,
stdio: ["pipe", "ignore", "pipe"],
});
let errorOutput = "";
zip.stderr.on("data", chunk => {
errorOutput += chunk.toString().slice(0, 1000);
});
zip.on("error", reject);
zip.on("close", code => {
if (code === 0) resolve(sourceArchivePath);
else reject(new Error(`Source archive creation failed (${code}): ${errorOutput}`));
});
zip.stdin.end(files.join("\n"));
}).catch(error => {
sourceArchivePromise = undefined;
throw error;
});
return sourceArchivePromise;
}
import express from "express";
import sharp from "sharp";
import { cookieParser, signPass } from "./utils.js";
import { beat } from "./server.js";
import "./discordbot.js"; // Discord bot (beta) — self-starts if DISCORD_BOT_TOKEN is set
import { app, io, server } from "./app.js";
import settings from "./settings.json" with { type: "json" };
import { isCloudflare, isLocal } from "./iputil.js";

export { app, io };

// Only trust forwarding headers from Cloudflare / a local reverse proxy, so a
// direct client cannot spoof X-Forwarded-For to forge req.ip.
app.set("trust proxy", (addr) => isCloudflare(addr) || isLocal(addr));

app.use(cookieParser);

app.use("/*.rss", (_req, res, next) => {
	res.setHeader("Content-Type", "application/xml; charset=UTF-8");
	next();
});

app.use((req, res, next) => {
	const randomToken = req.cookie.token ?? crypto.randomUUID();
	const cookieOpts = {
		maxAge: 31488000000,
		httpOnly: true,
		secure: true,
		sameSite: "lax",
		path: "/",
	};
	res.cookie("token", randomToken, cookieOpts);
	// Signed proof that this client actually loaded the page over HTTP. The
	// socket handshake guard (floodGuard) requires it, so off-site flood scripts
	// that connect straight to the socket — without ever fetching the page —
	// never receive it and are refused, even if they spoof the Origin header.
	res.cookie("pass", signPass(randomToken), cookieOpts);
	next();
});

app.get("/source-code.zip", async (_req, res) => {
try {
const archivePath = await ensureSourceArchive();
res.setHeader("Cache-Control", "no-store");
res.download(archivePath, "bonziworld-1.8.5-source.zip");
} catch (error) {
console.error("Unable to create source archive:", error);
res.status(500).type("text/plain").send("The source archive could not be created.");
}
});

// Resolve static directories from this file instead of the process working
// directory. This keeps the page and Socket.IO client assets available whether
// the server is started from `server/` or from the project root.
app.use(express.static(path.resolve(__dirname, "../build/www")));

app.get("/discord_pfp/:layers", async (req, res) => {
	try {
		let names = req.params.layers.slice(0, -4).split("+");

		if (names.length > 10) {
			return res.status(404).send("too much");
		}

		// Reject anything that isn't a plain layer name to prevent path traversal.
		if (names.some(n => !/^[A-Za-z0-9_-]+$/.test(n))) {
			return res.status(404).send("invalid layer");
		}

		let imagePaths = names.map(n => path.join(__dirname, "../client/src/img/pfp", `${n}.webp`));

		for (let p of imagePaths) {
			if (!fs.existsSync(p)) {
				return res.status(404).send(`Layer not found: ${path.basename(p)}`);
			} 
		}

		let base = sharp(imagePaths[0]);

		let overlays = imagePaths.slice(1).map(p => ({ input: p }));

		let result = await base
			.composite(overlays)
			.png()
			.toBuffer();

		res.set("Content-Type", "image/png");
		res.send(result);

	} catch (err) {
		console.error(err);
		res.status(500).send("Error generating image");
	}
});

export let port = Number(process.env.PORT || settings.port);

app.use((_req, res, next) => {
	res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
	next();
});

app.use(express.static(path.resolve(__dirname, "../client/src")));

await beat();

server.listen(port, "0.0.0.0", () => console.log("bonziworld.kr started"));
