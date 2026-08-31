# Nostr Key Transfer & Storage

This spec is a method to send and recieve Nostr secrets primarily by utilizing QR code and passphrases along with public servers with strong shoulder surfing resistance. It is a tiered system utilizing the most secure method of key management first: FROST, iCloud Storage, Google secure sync,  gift wrap, and is compatible with Bluetooth and LAN transfer. It is fully compatible with FROST and can silently upgrade with a compatible FROST server. When FROST is activated, there are protections from various angles of attack including single device compromise and single server compromise. Users are encouraged to make themselves secure as much or as little as they prefer and where robust defaults can be chosen for the user, within reasonable constraints, they are. 

The primary purpose of this project is to allow for increased security of key transfer and storage than the typical copy and paste method. Everything else we can reasonably do to increase security while maintaining a better user experience than that low bar, we attempt to do. 

## Elevator Pitch
A nostr identity is a private key and nothing else. There is no account to
recover, no provider to appeal to, and no agreed way to get that key onto a
second device. In practice people copy an nsec out of one app and paste it into
another, mail it to themselves, or photograph it, and when the first device is
lost the identity is lost with it. Every client solves this differently or not
at all, so the same user, holding the same key, gets a different answer about
what is safe depending on which app they happened to open.

This is a specification for that problem: how a client stores an nsec at rest,
how that nsec reaches a second device over a channel neither device controls,
and how it is backed up so that losing every device is recoverable rather than
final. It also specifies an optional threshold-signing mode in which no single
device, site, or server holds a usable copy of the key, and in which a device
can actually be revoked.

## Which file to read

[OVERVIEW.md](OVERVIEW.md) is the readable version: what the user sees and what
is underneath, in about four pages.
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) is the normative
specification, and governs wherever the two disagree.

## Why this is not NIP-46

NIP-46 is a signing protocol and this is a key lifecycle protocol. A remote
signer has to be reachable for every single signature, whereas a device that
has received a key under this specification needs nothing reachable at all,
ever again. And NIP-46 says nothing about how the signer's own key arrived on
that machine, how it is stored there, whether it is backed up, or what happens
when the machine is lost, which is the whole of what this document is about.

## Status

Version 8.0-rc1 is a release candidate rather than a finished standard, and
review is more useful right now than implementation, because three things are
genuinely missing: the event kinds are unregistered placeholders that will
change, there are no test vectors for any of the derivations, and Appendix A
specifies the constraints on the 64-entry emoji table without containing the
table, so the short authentication string is not yet reproducible across
implementations. Disagreements and suspected errors belong in
[SPEC_ISSUES.md](SPEC_ISSUES.md).
