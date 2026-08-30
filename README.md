# Nostr Key Transfer & Storage

A nostr identity is a private key and nothing else. There is no account to
recover, no provider to appeal to, and no agreed way to get that key onto a
second device. In practice users copy an nsec out of one app and paste it into
another, mail it to themselves, or photograph it — and when the first device is
lost, the identity is lost with it. Every client solves this differently or not
at all, which means the same user, on the same key, gets a different answer
about what is safe depending on which app they opened. This repository
specifies one answer: how a client stores an nsec at rest, how that nsec
reaches a second device over a channel neither device controls, and how it is
backed up so that losing every device is recoverable rather than final. It also
specifies an optional threshold-signing mode in which no single device, site,
or server holds a usable copy of the key, and in which a device can actually be
revoked — something base nostr cannot do at all.

## Where to start

Read [OVERVIEW.md](OVERVIEW.md) first. It is the readable version: what the
user sees, what is underneath, and why the defaults are what they are, in about
four pages.

[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) is the specification and is
the normative document. Where the two disagree, the specification governs. Its
MUST, MUST NOT, SHOULD, and MAY carry their usual meanings.

## What is reusable outside nostr

Several of the constructions here are not about nostr and could be lifted whole
into anything that has to move a secret between two devices a user owns. The
storage ladder in §2.1 is a platform-by-platform ranking of at-rest mechanisms
with the rule that every rung is acceptable and the client silently takes the
strongest one available, which generalises to any application holding a
long-lived secret. The degrade-never-block principle in §0 — that no addition
to the base may prevent a user from logging in, transferring, or using their
key on a device lacking a feature — is a design constraint, not a nostr fact.
The commit-reveal short authentication string in §3.3 is the ZRTP/Matrix
construction stated precisely enough to implement, and applies to any two
parties comparing a short code over an untrusted channel. The rule in §2.2 that
an action is privileged if and only if it touches the key itself, never the
content, is a general answer to the question of when an application should
prompt. And the blob-store construction in §7.2 is a stateless
password-protected backup service with its leakage properties stated honestly
rather than advertised, including what a two-store compromise does and does not
cost the user.

## Known gaps

**The event kinds are unregistered placeholders.** Every kind used here —
24301 through 24319, and the parameterised replaceable kind 30242 — was picked
to be plausible and unoccupied, not allocated. Anyone implementing against this
document today should expect all of them to change, and should not treat
interoperation with another implementation's choice of the same numbers as
meaningful. They will stop being placeholders only by going through a NIP, and
not before.

**There are no test vectors.** Two implementations cannot currently be shown to
agree on anything. The SAS derivation in §3.3 needs known-answer vectors for
the commitment, the code, and the emoji and digit extraction; the NIP-59
wrap-and-unseal path in §3.4 needs vectors covering the seal, the wrap, and the
expiration handling; the `ncryptsec` handling in §6 and §7.1 needs vectors at
both `log_n` values; and the §7.2 blob arithmetic — the scrypt derivation, the
`K_auth` and `K_wrap` HKDF steps, the `K_enc XOR K_srv` input, and the content-key
wrapping — needs vectors end to end. Until these exist, agreement between
implementations is an assertion rather than a fact.

**The emoji table does not exist yet.** Appendix A states the constraints on the
64-entry `EMOJI_TABLE` — visually distinct, fixed order, rendering identically
across iOS, Android, Windows and common browsers, no skin-tone modifiers, no
flags, no pairs differing only by colour — but does not contain the table. The
short authentication string is therefore not reproducible across
implementations, which makes §3.3 unimplementable in the interoperable sense
even though its construction is fully specified.

## Status

This is version 8.0-rc1: a release candidate, not a finished standard. The
design has been through several rounds of adversarial review and a number of
choices that look like weak defaults are deliberate and are argued for in
place — backup-only rather than threshold as the default, no password floor,
`lock = device` as the default unlock threshold. Given the three gaps above,
review is more useful right now than implementation. If you disagree with
something, or find something ambiguous, please record it in
[SPEC_ISSUES.md](SPEC_ISSUES.md) rather than deviating silently.

## License

[CC0 1.0 Universal](LICENSE). The specification is in the public domain
worldwide to the extent permitted by law, so that anyone may implement it,
fork it, or fold parts of it into a NIP without asking.
