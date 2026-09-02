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

**Threshold signing (optional), in two flavours.** Splitting the key so no single
device or site holds a usable copy comes two ways, and you pick the one that
matches what you have:

- **Device quorum.** Your key lives split across *your own devices*; any two of them
  sign together, and no server is involved at all. Nobody in the middle, nothing to
  be reachable but your devices. The trade: two devices present to post, and removing
  one re-keys the rest. This is the real upgrade to copy-pasting your nsec between
  your devices.
- **Co-signer.** A server you (or someone) runs holds one piece; your device holds
  the other; every signature needs both. This is what lets you log in on the web and
  cut off any device instantly — and unlike a remote signer, the server never holds
  your whole key and a breach of it can't post as you. The trade: the server must be
  reachable, and it sees what you post. This is the upgrade to a remote signer or a
  browser extension.

Both make it possible to actually revoke a device; both keep any one site or device
from holding a usable key.

**Recovery.** With a co-signer, it's the server address and a password, and if
threshold mode is on there's a delay — a day by default — during which your other
devices are told a recovery started and can approve or cancel it; with no devices
left, the delay just passes. A device quorum has no server to recover from: two
surviving devices already are the key, and below that you restore the backup you
were offered at setup — which is why, in that mode, skipping the backup makes your
devices the only copy.

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

**Server (optional).** Holds an encrypted backup of the key, and in co-signer mode
one share — never the whole key. The backup is protected by a password of the
user's choosing, and the setup screen says plainly that if the server is breached,
that password is the only thing left. Device-quorum mode uses no server at all.

**Threshold signing.** FROST over the same signature scheme Nostr already uses, so
signatures look ordinary to everyone else. Any two shareholders sign; the key is
never reassembled to do it. In device-quorum mode the two are two of your devices;
in co-signer mode they are a device and the server. Removing a device re-keys the
others (a rotation), which is what makes revocation real.

**Why the co-signer beats a remote signer on its worst day.** A remote signer or a
browser extension holds your *whole key* — breach it once and the attacker has
everything and can post anything. The co-signer holds one share: breach it and the
attacker gets something that is **not your key, can't sign on its own** (it can't
complete a signature without one of your devices), **and can't impersonate you**.
To actually reconstruct they'd have to breach one of your devices too — two
independent compromises instead of one. That's strictly better than every option
Nostr gives you today, on the exact surface (an always-online server) those options
are worst on.

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
- **Two shareholders who collude.** In any threshold scheme, any two who together
  meet the threshold can reconstruct the key by simply exchanging their pieces —
  there's no protocol step to log or refuse; it's what "threshold" means. In
  co-signer mode that pair is the server plus any one device; in device-quorum mode
  it's any two of your devices. Device quorum is the configuration where both
  colluders would have to be your own hardware — which is why its shares only ever
  go on devices you own.
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
