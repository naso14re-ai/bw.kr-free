// Discord bot for bonziworld.kr  (BETA)
//
// Runs in the SAME process as the game server so it shares the live Socket.IO
// instance — that's what lets a Discord command broadcast into BonziWORLD.
// It's loaded for its side effect (it self-starts), so index.js just needs to
// `import "./discordbot.js"` once.
//
// Setup:
//   1. npm install discord.js
//   2. In server/.env:
//        DISCORD_BOT_TOKEN=...        (required — the bot token)
//        DISCORD_CLIENT_ID=...        (the application/client id; optional, we
//                                      fall back to the logged-in user's id)
//   3. Invite the bot with the `applications.commands` (and `bot`) scopes.
//      /announce and /cctv register globally and can take up to an hour to first appear.
//
// Commands (beta):
//   /announce <message>   Broadcasts a site-wide announcement into BonziWORLD,
//                         credited to your Discord username.
//   /cctv [room]          Lists online rooms or details of a specific room.
import "./server.js";          // make sure the game-server module is loaded here
import { io } from "./app.js"; // the same Socket.IO instance the server runs on

const TOKEN = process.env.DISCORD_BOT_TOKEN;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const MAX_ANNOUNCE_LEN = 1000;
const ANNOUNCE_ROOM = "default"; // the public room id announcements go to

function discordCctv(roomId) {
    let target = (roomId || "").trim();
    if (!target) {
        let lines = [...rooms.values()]
            .sort((a, b) => a.id.localeCompare(b.id))
            .map((room) => `${room.id}: ${room.users.length} user(s)${room.owner ? ` owner=${room.owner}` : ""}`);
        return { title: "rooms", lines: lines.length ? lines : ["No rooms online."] };
    }
    let room = rooms.get(target);
    if (!room) return { title: target, lines: ["Room is not online."] };
    let lines = room.users.map((user) => {
        let anonId = anonIdForName(user.public.name, user.guid, user.databaseId);
        return `${user.public.name}${anonId ? ` (${anonId})` : ""}#${user.guid} ip=${user.getIp()} rl=${user.runlevel} room=${user.room.id}`;
    });
    return { title: target, lines: lines.length ? lines : ["Room is empty."] };
}

export async function startDiscordBot() {
    if (!TOKEN) {
        console.log("discordbot: DISCORD_BOT_TOKEN not set — Discord bot disabled.");
        return;
    }

    // Loaded lazily so the server still boots if discord.js isn't installed yet.
    let discord;
    try {
        discord = await import("discord.js");
    } catch {
        console.error("discordbot: discord.js not installed (run `npm install discord.js`) — bot disabled.");
        return;
    }
    const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, PermissionFlagsBits, MessageFlags, EmbedBuilder } = discord;

    const announceCommand = new SlashCommandBuilder()
        .setName("announce")
        .setDescription("Broadcast a site-wide announcement to BonziWORLD (beta).")
        .addStringOption((opt) =>
            opt.setName("message").setDescription("What to announce").setRequired(true)
        )
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .toJSON();

    const cctvCommand = new SlashCommandBuilder()
        .setName("cctv")
        .setDescription("View online rooms or specific room users (Admin only).")
        .addStringOption((opt) =>
            opt.setName("room").setDescription("Optional room ID to inspect").setRequired(false)
        )
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .toJSON();

    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    let registered = false;
    async function onReady() {
        if (registered) return;
        registered = true;
        console.log(`discordbot: logged in as ${client.user.tag}`);
        try {
            const rest = new REST({ version: "10" }).setToken(TOKEN);
            const appId = CLIENT_ID ?? client.user.id;
            await rest.put(Routes.applicationCommands(appId), { body: [announceCommand, cctvCommand] });
            console.log("discordbot: registered commands globally (global commands can take up to ~1h to first appear)");
        } catch (e) {
            console.error("discordbot: failed to register commands:", e.message);
        }
    }
    client.once("ready", onReady);
    client.once("clientReady", onReady);

    client.on("interactionCreate", async (interaction) => {
        if (!interaction.isChatInputCommand()) return;

        // Shared Admin protection checkpoint
        if (!interaction.inGuild() || !interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
            await interaction.reply({ content: "You must be a server administrator to use this.", flags: MessageFlags.Ephemeral });
            return;
        }

        const { commandName } = interaction;

        try {
            // === ANNOUNCE COMMAND ===
            if (commandName === "announce") {
                let message = (interaction.options.getString("message", true) || "").trim();
                if (!message) {
                    await interaction.reply({ content: "Nothing to announce.", flags: MessageFlags.Ephemeral });
                    return;
                }
                if (message.length > MAX_ANNOUNCE_LEN) message = message.slice(0, MAX_ANNOUNCE_LEN);

                const who = interaction.user.globalName || interaction.user.username;
                const roomKey = "#" + ANNOUNCE_ROOM;

                let online = 0;
                try {
                    online = io.sockets.adapter.rooms[roomKey]?.length || 0;
                } catch { /* ignore */ }

                io.to(roomKey).emit("alert", {
                    title: `Announcement from ${who} (Discord)`,
                    text: message,
                });
                console.log(`discordbot: /announce by ${who} -> ${online} client(s) in ${roomKey}: ${message}`);

                await interaction.reply({
                    content: online > 0
                        ? `Announced to BonziWORLD (${online} in the public room).`
                        : "Sent, but nobody is in the public room right now — or the bot isn't running inside the game server process (see console).",
                });
            }

            // === CCTV COMMAND ===
            if (commandName === "cctv") {
                const targetRoom = interaction.options.getString("room");
                const result = discordCctv(targetRoom);
                
                // Construct the embed
                const cctvEmbed = new EmbedBuilder()
                    .setTitle(` CCTV Monitor — Target: ${result.title}`)
                    .setDescription(`\`\`\`\n${result.lines.join("\n")}\n\`\`\``)
                    .setColor(0x5865F2) // Discord Blurple color
                    .setTimestamp();
                
                await interaction.reply({ embeds: [cctvEmbed], flags: MessageFlags.Ephemeral });
            }

        } catch (e) {
            console.error(`discordbot: error executing /${commandName}:`, e.message);
        }
    });

    client.on("error", (e) => console.error("discordbot: client error:", e.message));

    client.login(TOKEN).catch((e) => console.error("discordbot: login failed:", e.message));
}

startDiscordBot();