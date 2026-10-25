# onion-chat

A tiny end-to-end encrypted chat for one-to-one conversations, built to run as a Tor onion service.

- **One binary, about 6 MB.** Go standard library only, no dependencies. The web page is embedded.
- **No database, no accounts, no logs.** Users exist in memory while they're connected. Nothing is written to disk.
- **End-to-end encrypted.** Browsers agree on a key with ECDH, and the server only relays ciphertext.
- **No third-party anything.** No CDNs, fonts, analytics or trackers. A strict CSP blocks every outside request.

## How it works

1. Pick a username. Usernames are temporary and released when you leave.
2. Everyone online appears in a list. Click a name to send a chat request.
3. The other person accepts or declines. Once they accept, the chat is encrypted.
4. Click **Verify** and compare the 30-digit safety code over another channel. If both codes match, the server isn't in the middle.
5. **End** closes one chat. **Wipe** ends every chat, forgets everything and leaves. Closing the tab does the same.

Other features:

- Several chats at once, with unread counts.
- Typing indicator.
- Block someone to ignore their requests.
- Automatic reconnect when a Tor circuit drops.
- Works on phones.

## Security model

| | |
|---|---|
| Key exchange | Ephemeral ECDH P-256 per chat. Private keys are non-extractable and are discarded once the shared key is derived (forward secrecy). |
| Encryption | AES-256-GCM, with the key derived through HKDF-SHA-256. Each message has a random 96-bit IV. |
| Integrity | Sender and recipient names are bound in as associated data, so the server can't reflect or redirect messages. Sequence numbers reject replayed messages. |
| Verification | The safety code is SHA-256 of both public keys. A server that swapped keys would cause the two sides to see different codes. |
| Transport | The Tor onion service gives end-to-end transport encryption and hides both the server's and the users' IP addresses. |

**What the server can see:** which usernames are online and who is sending how many messages to whom. It can't read message contents.

**What it can't protect against:** a compromised browser or device, or an operator who changes the JavaScript the server sends. Like every web-based E2E app, you trust the server to deliver honest code each time the page loads. Self-host it if that matters to you.

**Browser support:** in Tor Browser, use the *Standard* or *Safer* security level. *Safest* turns JavaScript off, and the encryption needs JavaScript.

## Run locally

```sh
go build -trimpath -ldflags="-s -w" -o onion-chat .
./onion-chat            # listens on 127.0.0.1:8080
```

To try it, open http://127.0.0.1:8080 in two different browsers, or in a normal window and a private window.

## Host it as an onion service (Debian/Ubuntu)

```sh
# 1. Build on any machine. Cross-compiling is one command:
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o onion-chat .
scp onion-chat deploy/onion-chat.service you@server:

# 2. On the server:
sudo apt install tor
sudo install -m 755 onion-chat /usr/local/bin/
sudo cp onion-chat.service /etc/systemd/system/
sudo systemctl enable --now onion-chat

# 3. Add the lines from deploy/torrc.example to /etc/tor/torrc, then:
sudo systemctl restart tor
sudo cat /var/lib/tor/onion-chat/hostname   # your .onion address
```

The app only listens on `127.0.0.1`, so it can't be reached except through Tor. The systemd unit runs it as a throwaway user with no file access, only loopback networking and output sent to `/dev/null`.

## Limits

The limits are constants at the top of `main.go`:

- 500 users online at once
- 10 messages per second per user, with bursts up to 40
- 5 new usernames per second across the whole server
- 4,000 characters per message
- A username stays reserved for 20 seconds after a dropped connection, so reconnects keep the same name

## Files

```
main.go                     relay server (about 370 lines)
web/index.html, app.js, style.css   the client, including all crypto
deploy/onion-chat.service   hardened systemd unit
deploy/torrc.example        onion service config
```
