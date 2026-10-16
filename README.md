cd server then npm install then node index (on Windows, serverstart.bat also supports /restart).

Tests
-----

From the repository root, run `pnpm test`. The connection browser test starts
an isolated BonziWORLD server, drives the real client in headless Chromium, and
checks initial Socket.IO connection, outage messaging, and login recovery.

Configuration
-------------

Copy server/.env.example to server/.env, or provide the same values through
your deployment's secret manager. Direct runlevel-7 godword authentication is
disabled; normal Owners can only be granted by a Big Owner. The runlevel-8
credential is provided through `BIG_OWNER_GODWORD`.

Autoscaled replicas coordinate permanent-promotion outage alerts through
private App Storage using `DEFAULT_OBJECT_STORAGE_BUCKET_ID`. This setting is
required for server startup in deployment; do not replace it with replica-local
storage, or each replica can emit its own alert. The shared object contains only
the aggregate alert and expiry timestamps.

IP privacy is enabled by default. Admin-facing IP values are stable,
pseudonymous identifiers derived from the existing `SESSION_SECRET` with a
separate domain-specific hash. The server still uses the real socket address
internally for bans, rate limits, proxy checks, and ASN lookups; this avoids
turning privacy masking into an abuse-control bypass.
