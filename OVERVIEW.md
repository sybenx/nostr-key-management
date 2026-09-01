# Overview

The readable version. [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) and
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) are the normative documents
and govern wherever this disagrees with them.

This document deliberately avoids repeating parameters — code lengths, event
kinds, timeouts. Those live in the specs, and an overview that copies them goes
stale the first time one changes.

---

## The one idea

Your key lives on your devices. To put it on another one, you show a code on the
first, read it with the second, and type a short number back. Everything else —
encryption at rest, platform sync, backup, threshold signing — stacks on top of
that and can never take it away. If a device can't do one of those things, it
falls back to the layer below. Nothing stops you logging in.

## What a person actually does

**Adding a device.** One device shows a QR. The other reads it, by camera or by
pasting the link. Then the device that *has* the key asks you to type a short
number displayed on the device that's receiving it, and tells you plainly that
you are handing over your identity, not signing in. The receiving device shows
you whose account you're about to become, and you confirm.

The number matters more than it looks. Comparing two screens is something people
skip; typing a number is something you cannot do without having read the other
screen. That's the difference between a check that works and one that only
appears to.

**Storage.** Nothing to do. The app uses the strongest thing the device has —
platform keystore, a passkey-derived key, an encrypted browser key, or plain
storage on a device with none of those — and quietly upgrades if that changes.
Logging into the device is the unlock; the app doesn't ask again for ordinary
use. Rare, consequential actions — sending your key elsewhere, exporting it —
always ask, and that permission lasts for exactly one transfer.

**Backup.** Offered once at the end of setup: an encrypted file or printable
code, or a server. Skippable, and if you skip it the app never nags — the status
just sits in settings.

**Threshold signing (optional).** Splits the key so no single device, site or
server holds a usable copy, and makes it possible to actually revoke a device.
You need at least two devices, or a device and a server. The trade is that
posting now needs something else reachable, and whatever co-signs for you sees
what you post.

**Recovery.** Server address and password. If threshold mode is on there's a
delay — a day by default — during which your other devices are told a recovery
started and can approve or cancel it. With no devices left, the delay just
passes.

## What's underneath

**Transfer.** Both devices make throwaway keypairs used for one pairing and then
destroyed. The QR carries a public key and some relay addresses — never the
secret — so photographing it gets you nothing. The two devices exchange a
commitment and two random numbers, which is what stops an attacker in the middle
from working out a matching code. The secret then travels wrapped so that relays
see an anonymous blob addressed to a throwaway key: not the contents, not who
sent it, not that the two parties are related. Relays are used because they
already exist, nobody runs them for this purpose, and any of them can be swapped
for another mid-transfer.

**Storage.** A ladder, probed silently, strongest rung that works.

**Server (optional).** Holds an encrypted backup of the key, and in threshold
mode one share. The backup is protected by a password of the user's choosing, and
the setup screen says plainly that if the server is breached, that password is
the only thing left.

**Threshold signing.** FROST over the same signature scheme Nostr already uses,
so signatures look ordinary to everyone else. Any two shareholders can sign.
Adding or removing a device re-keys the others without the key ever being
reassembled.

## What this protects against, and what it doesn't

It protects against a relay or anyone watching one; a photographed or swapped QR;
a lost or stolen device, if threshold mode is on; and a hostile or breached
server, if threshold mode is on.

It does not protect against these, and the specs say so rather than implying
otherwise:

- **A website you hand your key to.** The code comparison proves you're talking
  to the device you think you are; it cannot tell you that device is honest. A
  site can behave correctly for everyone who reviews it and act only against one
  chosen person, so reputation is the wrong instrument. The only structural
  answer is not giving a website a usable key, which is what threshold mode is.
- **Two shareholders who collude.** In threshold mode any two of them can
  reconstruct the key by simply exchanging their pieces — there's no protocol
  step to log or refuse. Enrolling no server at all, and letting your own devices
  co-sign, is the only configuration where that has no second party.
- **A compromised device you're already using.** Same as any wallet.
- **Being wrong about the mathematics.** Every other failure has a fallback. This
  one doesn't, and because a Nostr key *is* the identity, there's no rotation in
  protocol to recover with. There is a social one — announce a new key from the
  old one while you still control it — but you lose your followers, your history's
  attribution and everyone who misses the announcement. Expensive rather than
  impossible, and it is what people actually do.

**Ordering matters more than any of the above.** Splitting a key doesn't change
it. If something already got a whole copy of your key, turning on threshold mode
afterwards does nothing — they keep a working copy permanently. It reduces the
attack surface going forward; it repairs nothing backwards. Protection has to be
in place before the first time you hand anything over, which makes it one of the
few security decisions that is genuinely worth making early rather than when it
becomes interesting.

## Where to read what

- [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) — the transfer mechanism.
  Self-contained; start here.
- [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) — storage, backup, threshold
  signing, and the two payload profiles.
- [SPEC_ISSUES.md](SPEC_ISSUES.md) — disagreements and suspected errors.
