# IRC Setup Guide

This guide walks you through configuring the IRC connector.

## Overview

The IRC connector is a thin raw-TCP client with IRCv3 capability negotiation and SASL `PLAIN` authentication. It does not add a new npm dependency. It speaks RFC 1459 over TLS by default and supports the three-factor trust model described below.

## Prerequisites

- A registered IRC nick on the target network (so you can identify to NickServer / use SASL).
- The bot nick's credentials (SASL password or NickServer password).
- A list of channels the bot should join on connect.
- A trust list mapping each allowed nick to its host glob — see "Trust model" below.

## Step 1: Decide on authentication

Pick one:

- **SASL `PLAIN`** — preferred when the network supports it. The bot sends credentials during the IRCv3 capability handshake. Set `irc.password` (and optionally a different `irc.username` if your network expects something other than the nick).
- **NickServer `IDENTIFY`** — used when SASL isn't available. Set `irc.nickservPassword`. The bot waits for the IDENTIFY NOTICE before joining channels.
- **Both empty** — the bot connects unauthenticated. The connector will still work, but if your nick is registered the server may reclaim it after a reconnect ghost cycle.

## Step 2: Configure `chat-bridge.json`

```json
{
  "irc": {
    "enabled": true,
    "host": "irc.libera.chat",
    "port": 6697,
    "tls": true,
    "nick": "your-bot-nick",
    "username": "your-bot-nick",
    "realname": "OpenCode Chat Bridge",
    "password": "{env:IRC_PASSWORD}",
    "nickservPassword": "{env:IRC_NICKSERV_PASSWORD}",
    "channels": ["#your-project"],
    "allowedUsers": [],
    "ignoreUsers": [],
    "respondToMentions": true,
    "maxLineBytes": 400
  }
}
```

The standard global `trigger` (`!oc` by default) is used unless overridden by `IRC_TRIGGER`.

## Step 3: Configure the trust list

IRC has weaker identity guarantees than any other supported platform. Nicks are trivially spoofable; only the network-issued cloak in `nick!user@host` is hard to forge, and even that requires the user to be identified to services.

The connector enforces all three of the following before treating a message as a command:

1. **Nick listed** in `irc.allowedUsers`.
2. **`host` matches the fnmatch glob** paired with that nick in the trust list.
3. **Nick is registered+identified to services**, confirmed via IRCv3 WHOIS (`RPL_WHOISREGNICK` 307 on Bahamut-style networks; `RPL_WHOISACCOUNT` 330 on charybdis/solanum/Libera).

`irc.allowedUsers` accepts one `<nick> <host_glob>` pair per entry. Example:

```
alice *.libera.chat
bob *.ofte.net
# Lines starting with # are comments; blank lines are ignored.
```

Inline:

```json
"allowedUsers": [
  "alice *.libera.chat",
  "bob *.ofte.net"
]
```

If any of the three checks fail, the message is still emitted to the agent context but tagged `UNTRUSTED` so the agent can see it without obeying it. **Private messages (QUERY) from unlisted nicks are dropped at the transport layer** — the payload never reaches the agent context, because by the time the system-prompt policy is applied, the text is already in the conversation.

If `irc.allowedUsers` is empty, every command will be rejected as `UNTRUSTED` and the connector will print a warning at startup.

### How to find your own host glob

Join the channel where you want the bot and type:

```
/whois your-nick
```

The server prints something like:

```
your-nick is your-nick!~you@user/account.frob.li.irc.libera.chat
```

Use `*.libera.chat` (or the appropriate trailing suffix) as the host glob for that account.

## Step 4: Run the connector

```bash
bun connectors/irc.ts
```

You should see:

```
[IRC] Starting...
  Trigger: !oc
  Server: irc.libera.chat:6697 (TLS: on)
  Nick: your-bot-nick
  Channels: #your-project
  Trust rules: 1
[IRC] TCP connected
[IRC] Registered as your-bot-nick
```

## Step 5: Invite the bot to a channel

In your IRC client:

```
/invite your-bot-nick #your-project
```

Or set `irc.channels` to join automatically on connect.

## Usage

In a joined channel:

```
!oc what's the current task status?
your-bot-nick: do a thing
your-bot-nick, ping when ready
```

In a private message:

```
/query your-bot-nick
hello there
```

Private messages from unlisted nicks are dropped silently. Listed nicks whose services registration is still pending are accepted but tagged `UNTRUSTED` until the WHOIS round-trip confirms their account.

Standard bridge commands work everywhere:

- `/help`
- `/status`
- `/clear` (also `/reset`) — discards the current channel's session

## Reconnect behaviour

The connector reconnects with exponential backoff (capped at 60s per attempt) after any socket drop. After ten failed attempts it exits non-zero so your process supervisor can restart it. Pre-001 nick collisions are handled by `NickServ GHOST` + `IDENTIFY`, mirroring the pattern in [vjt/claude-ircbot](https://github.com/vjt/claude-ircbot).

## Troubleshooting

**Bot never appears in channel.** Check the network's NickServ "group" permissions — some networks require you to `ADDUSER` your nick to the channel rather than `JOIN` it.

**Bot keeps getting GHOST-kicked by an older session.** Lower `irc.maxLineBytes` if a single response is too long and the server is splitting it into flood control violations.

**All commands are UNTRUSTED.** The WHOIS round-trip is async. The first PRIVMSG from a newly-listed nick will arrive before the 307/330 has been seen. Subsequent messages should pass. If every message is denied permanently, your network may not issue 307 or 330 — check `/whois your-nick` yourself and see whether the server reports an account.

**SASL fails silently.** Set `nickservPassword` as well and verify the connector sends `PRIVMSG NickServ :IDENTIFY`. If that succeeds, SASL is the wrong auth mechanism for this network.

## Security caveats

- IRC channels are plain text on the wire by default. `irc.tls` is `true` by default — keep it that way.
- Trust globs are matched case-insensitively. `*.libera.chat` matches any cloak issued by libera.chat; it does not authenticate that the user owns the underlying account.
- When `account-notify` / `extended-join` are advertised by the server, the connector uses the account name for verification; otherwise verification depends on WHOIS timing and may have a window where an unverified listed nick can issue commands. The recommended mitigation is keeping the trust list small and rotated.
- DCC file transfer (image upload) is intentionally out of scope for this connector. Images are surfaced as `[image: /path]` text references only.