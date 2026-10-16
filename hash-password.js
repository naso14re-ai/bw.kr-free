import crypto from "node:crypto";

const password = process.env.GOD_PASSWORD;
if (!password) {
  console.error("Set GOD_PASSWORD in the environment; do not pass it as a command-line argument.");
  process.exit(1);
}

process.stdout.write(
  crypto.createHash("sha256").update(password, "utf8").digest("hex") + "\n",
);