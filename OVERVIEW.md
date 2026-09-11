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

**Threshold signing (optional).** Splitting the key so no single device or site
holds a usable copy is [FROSTR](https://github.com/FROSTR-ORG/bifrost) — a
threshold-signing protocol and a family of apps (`igloo`) this project adopts
rather than builds. Any threshold of peers signs together; none holds a usable
key alone. Two shapes cover most setups:

- **All your own devices.** Any two (or more) of them sign together, and no
  server is involved at all. Nobody in the middle, nothing to be reachable but
  your devices. The trade: two devices present to post, and removing one means
  redoing the split. This is the real upgrade to copy-pasting your nsec
  between your devices.
- **A server as one of the peers.** A server you (or someone) runs holds one
  piece; your device holds another; a signature needs both. This is what lets
  you log in on the web and cut off any device instantly — and unlike a remote
  signer, the server never holds your whole key and a breach of it can't post
  as you. The trade: the server must be reachable, and it sees what you post.

Both make it possible to actually revoke a device; both keep any one site or
device from holding a usable key. This project's own part in either shape is
narrow: getting a share onto a new device without the plaintext QR scan
FROSTR's own apps use today.

**Recovery.** This project's own recovery — a server address and a password,
independent of whether FROSTR is in use — has a delay, a day by default,
during which your other devices are told a recovery started and can approve or
cancel it; with none reachable, the delay just passes. If FROSTR is in use, a
successful recovery puts the whole key back in one place while every peer's
share is still live elsewhere, which this project treats as unfinished: the
key isn't ready to use again until you re-split it with FROSTR, discarding
every pre-recovery share.

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

**Server (optional).** Holds an encrypted backup of the key, and where a server is
one of the FROST peers, one share — never the whole key. The backup is protected
by a password of the user's choosing, and the setup screen says plainly that if
the server is breached, that password is the only thing left. A device-only
threshold setup uses no server at all.

**Threshold signing.** FROST over the same signature scheme Nostr already uses, so
signatures look ordinary to everyone else. Any threshold of peers signs together;
the key is never reassembled to do it — sometimes that's two of your own devices,
sometimes a device and a server, sometimes more of either. This is FROSTR's own
mechanism, not something this project builds; what this project adds is a way to
neutralise a departed or compromised peer's retained share without reassembling
the key to do it (a rotation proposal, since FROSTR doesn't have one yet), which
is what makes revocation real rather than just a request for good behaviour.

**Why a FROST peer beats a remote signer on its worst day.** A remote signer or a
browser extension holds your *whole key* — breach it once and the attacker has
everything and can post anything. A FROST peer holds one share: breach it and the
attacker gets something that is **not your key, can't sign on its own** (it needs
a threshold of the other peers too), **and can't impersonate you**. To actually
reconstruct they'd have to breach enough other peers too — independent
compromises instead of one. That's strictly better than every option Nostr gives
you today, on the exact surface (an always-online server) those options are worst
on.

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
- **Shareholders who collude.** In any threshold scheme, any peers who together
  meet the threshold can reconstruct the key by simply exchanging their pieces —
  there's no protocol step to log or refuse; it's what "threshold" means. Where
  a server is one of the peers, that group includes it; where every peer is your
  own device, both (or all) colluders would have to be your own hardware — which
  is why a device-only setup's shares only ever go on devices you own.
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
- [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) — storage, backup, the two
  payload profiles, and this project's proposals to FROSTR (rotation, recovery
  delay). Threshold signing itself is specified by FROSTR, not here.
- [SPEC_ISSUES.md](SPEC_ISSUES.md) — disagreements and suspected errors.
