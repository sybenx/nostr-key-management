# Key Management — Overview

Companion to `NOSTR_KEY_MANAGEMENT.md` (the spec). This is the short version: what the user sees, and what's underneath.

---

## The one idea

Your Nostr key lives on your devices. To add a device, you scan a QR and tap once. Everything else — encryption, sync, backup, threshold signing — is stacked on top and can never take that away. If a device lacks a feature, it falls back to the layer below. Nothing blocks login.

---

## What the user sees

**Adding a device**
1. New device shows a QR. (No camera on the new device? Show the QR anyway — the phone scans it. No camera anywhere? Type a three-word code instead.)
2. Existing device scans it and shows four emoji plus a number, with what the new device claims to be: "Send your key to a browser at example.com showing 🦊🌊🔑🍕?" There's an unchecked box, "Trust this device (my own app)" — tick it for your own laptop app, leave it for websites. User taps Send.
3. New device shows the emoji; user taps the matching one and sees "Log in as @you?" — Yes.
4. Done. One tap on each device.

If the existing device is the one without a camera (a PC), it shows the QR and the phone scans it; then the PC asks "Approve login for the device showing 🦊🌊🔑🍕?" and the user taps Approve.

**Storage and unlocking**
Nothing to do. The app uses Face ID / Touch ID / Windows Hello / a passkey if the device has one, and plain storage if it doesn't. It quietly upgrades later if the user sets one up.

By default, logging into the device is the unlock — the app never asks again for normal posting, on any platform. Users who want more can pick "prompt at launch" or an idle timer; the choice travels with the key to new devices. Rare, high-consequence actions (sending your key to another device, exporting, rotating) always ask for a biometric or OS credential, whatever the setting.

If a QR or code gets scanned by more than one device, the screen that showed it says so — softly. The emoji check still decides who's real; the notice just tells you someone at the next table may have tried.

**Sync**
Nothing to do. On iPhone and Mac the key follows the user through iCloud Keychain. On Android it comes back through Google's app backup. Signing into a new phone in the same ecosystem just works — no QR.

**Backup**
At the end of onboarding: "Back up your key?" — export an encrypted file/printable QR, or connect a server. Skippable, and the app doesn't nag: backup status just sits in settings. Exports are always encrypted with a password of the user's choosing; the app never writes a raw key to disk.

**Connecting a server** (optional)
1. Scan the server's QR. Enter a password — any password; it's the user's call. The app offers a six-word generated phrase, pre-filled, which you can keep or replace. The screen says plainly: if this server is ever hacked, this password is the only thing protecting your key.
2. Choose:
   - **Backup only (default)** — key stays on your devices, server holds an encrypted copy, posting works offline.
   - **Threshold signing** — the key is split so no device or website holds a usable copy (the encrypted backup is the one full copy); any device can be revoked. Only offered if you have at least two devices, one of them a native app. Your server sees what your other devices post (not DM contents), and reading DMs on those devices needs the server or another device reachable, same as posting. Offline mode is for native apps, turned on ahead of time with a tap from another device.

**Recovering after losing everything**
Enter server URL and password. In threshold mode there's a safety delay (default a day): your other devices get told a recovery started and can approve it instantly or cancel it — so a stolen password alone can't silently become your key. With no devices left, the delay just passes and you're in.

**Threshold mode, day to day**
- Posts sign through the server, or another of your devices — whichever is reachable, over internet, Wi-Fi, or Bluetooth.
- Nothing reachable: the post waits and signs when something is; DMs wait to be read. Taking a laptop somewhere with no signal? Flip **Offline mode** on it first; another device taps Allow. Flip it off when you're back. Websites can't do Offline mode — a site holding two pieces would hold the key for good.
- Settings → Devices → Remove actually revokes that device.
- Settings → Devices → Remove site: kicks it out and re-keys everyone else, without the key ever being reassembled. Removing a *hacked server* does a full re-split instead, because a stolen piece can't be un-stolen by re-keying around it. Removing a *phone or laptop you lost* instead does a full re-split (briefly reassembles the key on your other trusted device, then splits it fresh) — because a lost device's old piece stays mathematically linked to everyone's current pieces otherwise. This is the answer to "my server got hacked" or "that website was sketchy."
- Removing a website removes it everywhere you'd logged into it (per site, not per browser).
- Websites you've logged into can read your DMs (through the server) as long as they're enrolled. The devices screen shows what each one has been doing, the server warns you if a site starts reading in bulk, and there's a "Websites can read DMs" switch.
- Changing the backup password or adding a second server never reassembles the key; only "turn threshold off" and "remove a lost device" do.
- Optional, if you have two native apps: "Two-device approval" — adding a device or turning threshold off needs a tap on both. Without it, a fully compromised phone plus your server is the key, same as a compromised phone is today.
- Optional: "Keep the full key on this device" for people who want their phone to work like before. Off by default; that device then can't be revoked.
- A lock in settings shows the state by colour *and* shape: green/check = split, green/phone = full key kept on a device, blue/figure = offline mode, amber/dots = pending, red/! = rotate recommended, grey/open = off.

---

## What's underneath

**Transfer.** Both devices make throwaway keypairs. The QR carries a public key only. The two devices exchange a commitment and two random nonces (so a man-in-the-middle can't grind a matching code), both screens show the same emoji code, and only after the user confirms it on the key-holding device does the nsec travel — inside a NIP-59 gift wrap, encrypted so relays see nothing, over public relays or the local network. A substituted QR produces emoji that don't match. A phishing page pretending to be your login does *not* — it shows matching emoji — so the confirm button on the key-holding device says what the other side claims to be ("a browser at example.com"). That line is the defence; read it. Off-grid with no network at all, the app can show an encrypted-nsec QR (NIP-49) as a last resort.

**Storage ladder.** Platform keystore with biometric → passkey-derived key (browser) → non-extractable browser key → plain app storage. Probed silently, strongest available wins.

**Server.** Holds two things: an encrypted backup of the full key (scrypt at 256 MiB per guess, with a second key kept in a separate secret store so a leaked database is useless on its own, and a password proof so the server can rate-limit guesses instead of handing out the ciphertext; if the whole server is compromised, the password is the only thing left — the setup screen says exactly that), and — only in threshold mode — one share of the split key.

**Threshold signing (FROST).** 2-of-N over BIP-340 Schnorr. The server holds share 1; every extra server holds the *same* share 1, so redundant servers add availability without adding attack surface. Devices hold shares 2..N. Rotation is a refresh: one trusted device picks a random number and sends each member a delta; shares change, the key doesn't, and nothing is ever reassembled. Every old share is dead the moment the epoch ticks. Adding a device after activation is done jointly by an existing device and the server, each sending a blinded partial — no key is ever assembled.

**Why default to backup-only.** Offline posting is normal on Nostr. Threshold signing trades it for revocability, and it lets your server see what your other devices post. That's a threat-model choice the user makes, not one the app makes for them.

**What threshold mode does and doesn't protect against.** It protects against a hostile website, a hacked or dishonest server, and a lost laptop. It does not protect against a rooted phone — that's the same "lost unlocked phone = lost key" that Nostr has always had, unless you turn on two-device approval.

---

## Files

- `NOSTR_KEY_MANAGEMENT.md` — the normative spec: exact flows, message kinds, parameters, UX copy.
- `OVERVIEW.md` — this document.
