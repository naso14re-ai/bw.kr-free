import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function spawnRestartChild() {
	const startScript = path.join(__dirname, "index.js");
	let child;

	if (process.platform === "win32") {
		child = spawn("cmd.exe", [
			"/d",
			"/s",
			"/c",
			`cd /d "${__dirname}" && timeout /t 1 /nobreak >nul && "${process.execPath}" "${startScript}"`
		], {
			cwd: __dirname,
			detached: true,
			stdio: "inherit",
			env: process.env,
			windowsHide: true,
		});
	} else {
		child = spawn("/bin/sh", [
			"-c",
			"sleep 1; exec \"$1\" \"$2\"",
			"bonziworld-restart",
			process.execPath,
			startScript,
		], {
			cwd: __dirname,
			detached: true,
			stdio: "inherit",
			env: process.env,
		});
	}

	child.unref();
	child.on("error", (error) => {
		console.error("restart: failed to spawn child process", error);
	});

	return child;
}
