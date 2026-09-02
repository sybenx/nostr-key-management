# QR Secret Transfer — Specification

Version 1.1-draft
Applies to: any two devices moving a secret between them under user supervision

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

A secret moves between two devices over infrastructure that neither device
operates, registers with, or trusts. One device shows a QR code, a person
carries a short code between two screens, and the secret travels encrypted.

Every addition MUST degrade to that base mechanism. Nothing in this
specification may prevent a transfer that the user has authorised and that both
devices are capable of performing.

## 1. Overview

The QR carries an address at which the showing device can be reached, plus
transport hints. It never carries the secret, except in the offline fallback of
§10, which has its own encryption.

1. One device generates a burner keypair and shows its public half as a QR.
2. The other scans it and generates its own burner keypair.
3. The two exchange a commitment and two nonces, from which both derive the same
   five-digit code.
4. A person carries that code from one screen to the other.
5. Only after the code is verified does the secret travel, encrypted end to end.
6. Both burner keypairs are destroyed.

§§3–10 state what the mechanism needs without assuming how it is provided. §11
is the Nostr binding and is the only binding defined here.

## 2. Definitions

- **Sender** (`SND`) — the party that holds the secret and releases it.
- **Receiver** (`RCV`) — the party that obtains it.
- **Burner** — an ephemeral keypair created for one session and destroyed after.
  `SND.pub` and `RCV.pub` are the burner public keys.
- **Session** — one transfer attempt. Lifetime 10 minutes. Burners MUST NOT be
  reused across sessions.
- **Contacting party** — whichever party scans the QR and speaks first: the
  Sender in Flow A (§7), the Receiver in Flow B (§8).
- **Profile** — the definition of one kind of payload (§5).
- **Payload** — the secret being moved, as bytes, opaque to this specification.

Roles are named by what a party does with the secret, never by which party shows
the QR.

## 3. Transport contract

A conforming transport MUST provide:

- **T1 — Ephemeral addressing.** A party can be addressed at a freshly generated
  public key, with no prior registration and no relationship between that key and
  any long-lived identity.
- **T2 — No account.** Neither party holds an identity, credential, or
  relationship with the transport operator. Nothing is provisioned to begin a
  session.
- **T3 — Confidentiality.** Message contents are unreadable by the operator and
  by third parties.
- **T4 — Unlinkability to long-lived identity.** The operator cannot link a
  session to either party's long-lived identity. It is **not** a requirement that
  the operator be unable to pair the two halves of a session with each other; see
  §15.
- **T5 — Sender attribution.** Each delivered message carries a verifiable
  indication of which burner sent it, unforgeable by the operator or a third
  party. Every "verify attribution" step in §§6–8 depends on this.
- **T6 — Capacity.** A single message carries at least the maximum payload
  declared by the profile in use (§4, P1).
- **T7 — Untrusted operator.** The operator may drop, delay, and observe
  messages. It MUST NOT be able to forge or substitute them undetectably.
- **T8 — Expiry.** A message can be given a bounded lifetime.
- **T9 — Liveness within the session.** Best-effort delivery inside the
  ten-minute window. No ordering guarantee beyond what the flows enforce.

## 4. Payload requirements

### P1 — Bounded size

One payload, one message. The transport nests and re-encrypts the payload, which
expands it — under §11, ×3.4 for binary payloads and ×4.7 for hex-encoded ones,
so a 32-byte secret occupies about 1.9 KB on the wire.

The default maximum payload is **2048 bytes binary**, which is carried by
operators at every limit observed (§11.6). A profile MAY declare a larger
maximum; where it does, clients MUST read the transport's advertised limits
during the §11.3 probe and MUST skip operators that cannot carry the declared
maximum.

Payloads SHOULD be base64 rather than hex, which costs roughly 40% of the budget
for no benefit. Profiles carrying tens of bytes MAY use hex.

A conformance test vector MUST exist at exactly the declared maximum.

### P2 — Single-shot

One payload, one session. Chunking, fragmentation and resumption MUST NOT be
attempted.

**Companion messages.** A profile MAY define additional, semantically distinct
messages in the same session, subject to all of:

- At most **three** per session, each individually within P1.
- Sent alongside the payload, not after it. The Sender emits them in the same
  session without waiting; the Receiver holds them under P6 keyed by the sending
  burner and commits them only together with the payload they arrived beside.
  Companions from a burner whose payload is never committed are discarded with
  it.
- Covered by the same release consent. §9's prompt MUST name the companions.
- Not required for completion. A Receiver that never gets them MUST still hold a
  usable payload, MUST NOT make the user's ability to confirm contingent on
  their arrival, and MUST commit the payload whether or not any arrived. It MAY
  wait a bounded, short interval after confirmation for companions still in
  flight, provided expiry commits the payload regardless.

### P3 — Opaque to the carrier

The mechanism MUST NOT parse, validate, or depend on the structure of the
payload.

### P4 — Identifiable against the declared profile

The Receiver MUST be able to determine that what it received belongs to the
profile declared in the QR (§11.2, `p=`), and MUST abort if it does not. The
check is defined by the profile.

### P5 — Renderable to a person

A profile MUST define a human-meaningful rendering of the received payload, shown
for confirmation before the payload is committed to storage (§9). A payload that
cannot be meaningfully summarised to its recipient MUST NOT use this mechanism.

### P6 — Safe to hold and discard

A Receiver may hold several candidate payloads simultaneously (§13) and commits
at most one. A payload MUST tolerate being received, held, and wiped without side
effects. Implementations MUST bound the number held (§9, §13).

### P7 — Confidentiality from the transport, except offline

A payload need not encrypt itself; T3 covers it. The exception is the offline
fallback (§10), which has no transport. A profile that permits offline transfer
MUST define its own passphrase-based encryption for that case.

## 5. Profiles

A profile defines one kind of payload. It is identified by a string matching
`[a-z0-9-]{1,24}`, carried in the QR, and MUST specify:

1. The payload encoding and its meaning.
2. Its maximum payload size, if larger than the P1 default.
3. The check satisfying P4.
4. The rendering satisfying P5.
5. Its confirmation copy for §9 — what the Sender's prompt says is being sent.
6. Whether the offline fallback (§10) is permitted, and if so the encryption
   satisfying P7.
7. Any additional message tags, which MUST NOT collide with the reserved names
   in §11.4.
8. Any companion messages (P2): what each carries, the value of its `companion`
   tag (§11.4), and the wording by which §9's release prompt names them.

A profile MAY restrict which parties are permitted to act as Sender, and MAY
disallow the offline fallback entirely. Implementations MUST ignore tags they do
not recognise.

Profiles are defined outside this document. `nostr-nsec` and `frost-share` are
defined in the Nostr key storage specification.

### 5.1 Non-normative example

> **Profile `example-token`.** Payload: a bearer token, UTF-8, base64. Default
> size. P4 check: decodes as valid base64 and parses as a JWT with a recognised
> issuer. P5 rendering: "a token for *example.com*, issued 14 March, expiring 21
> March." Sender prompt: "Send your example.com token to …". Offline fallback:
> not permitted.

## 6. Session and short authentication string

The contacting party commits to a nonce before the other reveals its own. The
code derives from both burners and both nonces.

```
contacting party:  nonce_C ← random 32 B
                   commit  = SHA-256("qrst-commit-v1" || C.pub || nonce_C)
                   sends { C.pub, commit }
other party:       nonce_O ← random 32 B;  sends { nonce_O }
contacting party:  sends { nonce_C }
both:              verify SHA-256("qrst-commit-v1" || C.pub || nonce_C) == commit
                   code    = SHA-256("qrst-sas-v1" || len(p) || p
                                     || SND.pub || RCV.pub || nonce_S || nonce_R)
                   digits  = (code[0..5] as u40 BE) mod 100_000, zero-padded to 5
```

`SND.pub` and `RCV.pub` are the 32-byte burner public keys in role order,
regardless of flow. In Flow A the contacting party `C` is the Sender, so
`nonce_C = nonce_S`; in Flow B it is the Receiver. `p` is the profile identifier
from the QR (§11.2) as ASCII, preceded by its length as a single byte.

The transcript binds the protocol version, the profile, both burners, the role
each holds, and both nonces. It does **not** bind the relay set or the chosen
transport: §11.3 permits the relay and local paths to be raced and permits
falling back between them mid-session, and a transcript committing to the
transport would render every such recovery indistinguishable from an attack.

Neither party transmits the code. Each derives it independently, and it reaches
the other device through a person (§9).

An attacker who is in the middle gets one attempt per session. Attempts
accumulate across *sessions*, not within them, which is what §9's restart
throttle bounds.

| Sessions | Cumulative risk |
|---|---|
| 1 | 1 in 100 000 |
| 10 | 1 in 10 000 |
| 100 | 1 in 1 000 |

Cost: one extra message on the contacting side. Both flows are four messages
before the payload moves.

## 7. Flow A — Receiver shows the QR

Used when the Receiver cannot scan (desktop, browser), or whenever the Sender is
a phone.

```
Receiver                                    Sender
--------                                    ------
1. gen burner RCV
2. begin listening at RCV.pub
3. show QR: mode=offer, p=<profile>
                                            4. scan QR; verify it implements p,
                                               else abort before generating
                                               anything
                                            5. gen burner SND, nonce_S
                                            6. send HELLO(SND.pub, commit)
                                               → RCV.pub
7. receive HELLO; verify attribution (T5);
   gen nonce_R for this SND
   (a HELLO from a second distinct burner
    → §13; keep each with its own nonce_R)
8. send NONCE(nonce_R) → SND.pub
                                            9. receive NONCE
                                           10. send REVEAL(nonce_S) → RCV.pub
                                           11. derive SAS; show the consent
                                               prompt of §9
12. receive REVEAL; verify commit; derive
    SAS for this SND; DISPLAY the code
    (all candidates, at most 3, newest
    first): "Type this on your other
    device"
                                           13. user obtains a code from the
                                               Receiver's screen (§9); match → 14
                                               declines or 5 failures → abort,
                                               zeroize SND
                                           14. send PAYLOAD → RCV.pub
15. receive payload and any companions;
    verify attribution; hold keyed by
    sending burner. MUST NOT commit
16. if more than one payload is held, user
    selects by code; applies the P4 check;
    renders per P5 ("Log in as @name?");
    asks to confirm
17. confirmed → commit payload and the
    companions held beside it; send ACK
    → SND.pub; zeroize RCV and every other
    held payload
    declined → discard all, abort
                                           18. zeroize SND on ACK or after 60 s
```

Step 13 authorises *release*; steps 16–17 authorise *acceptance*. Both are
required.

## 8. Flow B — Sender shows the QR

Used when the Sender cannot scan (camera-less desktop, browser).

```
Sender                                      Receiver
------                                      --------
1. gen burner SND
2. begin listening at SND.pub
3. show QR: mode=request, p=<profile>
                                            4. scan QR; verify it implements p,
                                               else abort
                                            5. gen burner RCV, nonce_R
                                            6. send REQUEST(RCV.pub, commit)
                                               → SND.pub
7. receive REQUEST; verify attribution;
   gen nonce_S for this RCV
8. send NONCE(nonce_S) → RCV.pub
                                            9. receive NONCE
                                           10. send REVEAL(nonce_R) → SND.pub
                                           11. derive SAS; DISPLAY own code —
                                               "Type this on your other device:
                                                [digits]"
12. receive REVEAL; verify commit; derive
    SAS; show the consent prompt of §9
13. user obtains the code shown on the
    Receiver's screen (§9); match → 14
    (declines → discard this RCV; show the
     next pending request, if any, or keep
     waiting; abort only at 10 min)
14. send PAYLOAD → RCV.pub
                                           15. receive payload and any companions;
                                               verify attribution and that the
                                               sending burner is the SND.pub from
                                               the QR, else discard
                                           16. apply P4 check; render per P5;
                                               ask to confirm
                                           17. confirmed → commit; send ACK
                                               → SND.pub; zeroize RCV
18. zeroize SND on ACK or after 60 s
```

Requests are queued by distinct Receiver burner in arrival order, capped at
**five pending per session**; further distinct requests are dropped with the §13
notice. Each queued request runs its own nonce exchange, and at most **three**
are presented for approval at a time, newest first — the same display cap as
Flow A, and the reason §9's attempt budget exceeds it. Declining advances to the
next or returns to waiting; the session ends on approval or at ten minutes.

In Flow B the Receiver has no independent screen to compare against before it
sends its request: the SAS is shown to it at step 11 and to the Sender at step
12, and the Sender acts on the comparison. The Receiver's acceptance
confirmation at step 16 remains required.

## 9. Consent and confirmation

Two distinct user actions, on two devices. Both are mandatory and neither may be
defaulted, remembered, or suppressed.

### 9.1 Release consent, on the Sender

Before any payload is sent, the Sender MUST present a prompt that:

1. Names what is being sent, in the profile's words (§5, item 5), and any
   companions (§4, P2). It MUST state that the secret itself leaves this device —
   not a session, not a revocable permission. Where the profile's secret cannot
   be revoked once released, the prompt MUST say so.
2. Names what the other party claims to be: for a browser, its origin; otherwise
   that it is a native application. These are unverified claims. Origins
   containing non-ASCII MUST be shown as punycode.
3. Presents the means of obtaining the Receiver's code. The Sender MUST NOT
   display the code it derived itself.
4. Requires a deliberate action. The Sender MUST NOT release before it.

**The heading MUST contradict the expected mental model** — a person who has just
scanned a QR believes they are signing in. For example: *"This is not a login.
You are about to give this device your key."*

**Declining MUST be the prominent control.** The affirmative control MUST NOT be
visually dominant, MUST NOT be focused or default, and MUST NOT be activated by a
default keyboard action. Where the controls carry text, the affirmative one MUST
describe the transfer rather than express agreement: "Send my key to that device"
rather than "OK" or "Continue".

**Friction is graduated by what the other party claims to be:**

- **A web origin.** Maximum friction. The prompt SHOULD require an additional
  deliberate act beyond a single tap, and MUST name the origin in the affirmative
  control itself.
- **A native application.** Standard friction. Deliberate and unambiguous, but
  not alarming.

**Authorisation is scoped to one session and MUST NOT outlive it.** Consent, and
any platform credential or biometric check a profile requires alongside it (§5),
authorise exactly one transfer session. They MUST NOT be remembered, defaulted,
cached, or carried into a subsequent session, and MUST NOT open a period during
which further transfers proceed unchallenged.

### 9.2 Obtaining the code

**The Sender MUST obtain the Receiver's code from the Receiver's display and
verify it locally.** Two conforming methods; an implementation MAY offer either
or both:

- **Entry.** The user reads the digits and types them.
- **Capture.** The user points this device's camera at the Receiver's display and
  the code is read optically. A Receiver SHOULD render its code in a
  machine-readable form alongside the human-readable one.

**Confirmation alone does not conform.** A control that merely asks whether the
codes match — a tap, a button press, a biometric prompt — MUST NOT be used in
place of entry or capture. Where a profile requires such a check as well (§5), it
is complementary and never a substitute.

- Where entry is used, the field MUST show five discrete character positions, MUST
  accept exactly five digits, and MUST NOT silently accept more.
- The field MUST NOT be pre-filled and MUST NOT be auto-completed from the
  clipboard.
- Where capture is used, a captured code that does not match counts as an
  attempt.
- Where the Receiver holds more than one candidate (§13) it displays each
  candidate's digits, at most three. The Sender's user types codes from that
  screen until one is accepted or the budget is spent.
- At most **five** attempts per session — more than the three candidates that can
  be displayed. On the fifth failure the Sender abandons the session and zeroizes
  its burner.

**The code is never transmitted, and the comparison is never delegated.**

- The obtained value MUST NOT be sent to the peer, in any form, encrypted or not.
- The Sender MUST compare it against the value it computed itself. A comparison
  result asserted by the peer MUST NOT be accepted under any circumstances.
- The obtained value MUST NOT be written to logs, analytics, crash reports, or any
  storage that outlives the session.

**It is not a PIN and MUST NOT be called one.**

- Interfaces MUST NOT label it "PIN", "passcode", or anything the user might
  possess independently. It is a *pairing code*, belonging to one session.
- The prompt MUST state where the code comes from — "the code shown on your other
  device" — rather than asking for "your code".
- Implementations MUST NOT request this code anywhere outside an in-progress
  transfer.

### 9.3 Restart throttle

Attempts within one session give an attacker nothing; every fresh chance comes
from a new session (§6).

- On exhausting its attempts the Sender zeroizes its burner and ends the session.
  The client MUST return the user to the scan step. It MUST NOT offer to re-enter
  a code, reopen the entry field, or resume the session in any way.
- **The Sender MUST NOT begin a new session with a peer burner it has already
  failed a code entry against**, and MUST remember those burners for at least one
  hour.
- The Sender SHOULD send `ABORT` (§11.4) before zeroizing. Its absence means
  nothing and MUST NOT be relied on.
- After **three** failed sessions within one hour, the client MUST tell the user
  that repeated failures can indicate interference rather than mistyping, and
  SHOULD require an explicit acknowledgement before another attempt.

### 9.4 Acceptance confirmation, on the Receiver

Before a payload is committed, the Receiver MUST require the user to select the
SAS matching the Sender's screen from the candidates it holds, MUST then show the
P5 rendering, and MUST require confirmation.

This side MUST NOT be presented as alarming. The confirmation is nonetheless
mandatory: it is what prevents a party who photographed the QR from racing the
real Sender and planting their own payload.

## 10. Offline fallback

Available only when no transport is reachable, the user confirms they are
offline, and the profile permits it (§5). The payload travels inside the QR
itself, so every property of §3 is forfeited and the payload's own encryption is
all that remains (P7). There is no SAS in this flow.

1. The Sender prompts for a passphrase, with the line **"Anyone who photographs
   this code can try passwords against it forever; this passphrase is the only
   protection."**
2. The Sender displays the profile's passphrase-encrypted encoding of the payload
   as a QR. The screen sets the platform screenshot-block flag and auto-dismisses
   after 60 seconds. Where no reliable flag exists — X11 has none, Wayland is
   compositor-dependent — the Sender MUST display an explicit warning that
   screenshots cannot be blocked, and MAY then proceed.
3. The Receiver scans, prompts for the same passphrase, decrypts, applies the P4
   check, renders per P5, and asks to confirm before committing.
4. The Sender records a transfer event with the offline flag set (§14).

## 11. Transport binding: Nostr

**This is the only Nostr-dependent section.** A different binding replaces this
section and nothing else.

### 11.1 How the contract is satisfied

| Requirement | Provided by |
|---|---|
| T1 ephemeral addressing | secp256k1 burner keypairs; wraps addressed by `p` tag |
| T2 no account | relays accept unauthenticated publishes; burners are unregistered |
| T3 confidentiality | NIP-44 v2, twice — rumor to seal, seal to wrap |
| T4 unlinkability to long-lived identity | burner keypairs; NIP-59 random one-time wrap signing key |
| T5 sender attribution | the seal (kind 13) is signed by the sending burner |
| T6 capacity | §11.6 |
| T7 untrusted operator | relays cannot forge a seal signature |
| T8 expiry | NIP-40 `expiration` tag, advisory only; see §11.4 |
| T9 liveness | relay subscription for the session's duration |

NIP-59's `created_at` randomisation maps to no row above and is **not** used; see
§11.4.

### 11.2 QR URI

```
qrst://<npub>?v=1&mode=<offer|request>&p=<profile-id>[&relay=<wss url>]*[&local=<ws url>][&origin=<host>]
```

- `npub` — bech32 burner public key of the device showing the QR.
- `mode=offer` — the showing device is the Receiver (Flow A).
- `mode=request` — the showing device is the Sender (Flow B).
- `p` — profile identifier (§5). REQUIRED; it is hashed into the SAS (§6), so an
  optional field would need a canonical encoding for its absence and two
  implementations would choose differently.
- `relay` — 1–4 relay URLs the showing device is subscribed to.
- `local` — optional LAN endpoint, e.g. `ws://192.168.1.23:53317`.
- `origin` — REQUIRED if and only if the showing device is a web client, and
  omitted otherwise. Its presence is what selects the web tier of §9's graduated
  friction. It is an unverified claim.

A client MUST reject URIs with unknown `v`, missing `mode`, or missing `p`, and
MUST abort before generating a burner if it does not implement the declared
profile.

**Role collision.** A client that has already committed to a role MUST reject a
URI whose `mode` implies that same role, and MUST say so rather than failing
later. A client that has not yet committed adopts the complementary role.

Profiles MAY register additional `mode` values.

### 11.2a Carrying the URI in an `https` link

A QR SHOULD encode the URI as an `https` link with the complete `qrst://` URI in
the **fragment**, so that neither the burner key nor the relay list reaches the
origin's server or its logs:

```
https://<origin>/<path>#qrst://<npub>?v=1&mode=…&p=…
```

- A client whose own camera reads the code MUST extract the URI from the fragment
  and MUST NOT make the request.
- The `origin` SHOULD be the one already serving the client that drew the code.
- The landing page SHOULD be a bounce page: it reads its own fragment, offers the
  `qrst://` deep link, offers the URI as copyable text, and acts as a party itself
  only if the visitor chooses that origin's own client. Because the fragment never
  reaches the server, such a page can be entirely static.
- `qrst://` remains valid and is the RECOMMENDED form for deep links and copied
  text (§12.1).
- The additional friction §12.1 requires for a pasted URI applies identically to a
  scanned `https` code that was not read by the client's own camera.

### 11.2b Presenting the code

**A QR MUST NOT be displayed bare.** It is accompanied by a line, in the user's
language, stating the direction and what will move: "Scanning this sends your key
to this device", "This device is receiving a key". The profile supplies the
wording (§5, item 5).

**Release and receipt MUST look different.** A `mode=offer` code, which makes
whoever scans it the Sender, is presented with visibly greater weight than a
`mode=request` code.

**Overlays.** Implementations MAY place a logo or wordmark at the centre of the
code. An implementation that overlays anything MUST raise error correction to
level **H**, MUST keep the overlay under 25% of the code's area, and SHOULD verify
its codes still scan at the smallest screen size it supports.

**No overlay may imply assurance.** Whatever sits in that space MUST NOT be a
badge, seal, shield, tick, padlock or ribbon, and MUST NOT be rendered in whatever
colour the implementation uses elsewhere for success, verified or trusted states.
This specification defines no mark of its own.

Implementations MUST NOT relax any consent step of §9 on the basis of anything
rendered on or beside the code.

### 11.3 Transport selection

Before showing transfer UI, the client probes in parallel, timeout 3 s:

1. Relay reachability — WebSocket open and `REQ` accepted on at least one
   configured relay.
2. Local network reachability — mDNS browse for `_qrst._tcp`, or a `local=`
   endpoint from a scanned QR.

The transfer uses relays if reachable, else the local network, else §10. Both
paths MAY be attempted concurrently; the first payload successfully received
completes the session and the other is cancelled.

**For a client with only one transport available in its current role, the probe
is advisory rather than selective:** the client MUST show transfer UI, MUST
re-attempt the unreachable transport for the remaining lifetime of the session,
MUST proceed as soon as a transport becomes available, and MUST report failure
only once the session has expired. A three-second probe MUST NOT close out a
ten-minute session. Browsers have no mDNS and cannot open `ws://` to private
addresses from `https://`, so a browser has relays or §10 and nothing else.

### 11.4 Messages

```jsonc
// HELLO — Sender → Receiver (Flow A): the Sender's commit
{ "kind": 24401, "content": "", "tags": [["commit","<hex>"]] }

// REQUEST — Receiver → Sender (Flow B): the Receiver's commit
{ "kind": 24402, "content": "", "tags": [["commit","<hex>"]] }

// NONCE — non-contacting party → contacting party
{ "kind": 24403, "content": "", "tags": [["nonce","<hex>"]] }

// REVEAL — contacting party opens its commit
{ "kind": 24404, "content": "", "tags": [["nonce","<hex>"]] }

// PAYLOAD — Sender → Receiver
{ "kind": 24405, "content": "<profile-defined>", "tags": [] }

// ACK — Receiver → Sender, after the payload is committed
{ "kind": 24406, "content": "", "tags": [] }

// ABORT — either party → peer, this session is over (§9.3)
{ "kind": 24407, "content": "", "tags": [] }

// COMPANION — Sender → Receiver, emitted alongside the payload (§4)
{ "kind": 24408, "content": "<profile-defined>", "tags": [["companion","<profile-defined name>"]] }
```

All kinds are unregistered placeholders and will change; they should be reserved
in the kind registry before implementations ship.

Reserved tag names: `commit`, `nonce`, `companion`. Profiles MAY add tags to any
message; implementations MUST ignore tags they do not recognise.

The session's protocol version is fixed by the QR's `v` (§11.2) and bound into the
SAS domain separators (§6). Messages carry no version tag.

**Companions share one kind.** Every companion a profile defines uses kind 24408
and is distinguished by its `companion` tag, whose values the profile assigns (§5,
item 8). A Receiver MUST ignore a companion whose name it does not recognise and
MUST NOT treat it as an error. The three-per-session cap of §4 counts every kind
24408 rumor in the session, recognised or not.

These are unsigned rumors. **Every one of them** is sealed — kind 13, signed by
the sending burner, NIP-44 to the recipient burner — and gift-wrapped — kind 1059,
random one-time signing key, `p` tag set to the recipient burner. There are no
exceptions.

**Timestamps.** Contrary to NIP-59, the wrap's `created_at` MUST be the true
current time rather than a randomised past value. The randomisation exists to
obscure authoring time for asynchronous correspondents; here every wrap is
published immediately, both parties are single-session burners, and the
randomisation buys nothing while forcing a 48-hour subscription window and a
second timestamp to reason about.

- The wrap MUST carry `["expiration","<now + 600>"]` per NIP-40.
- **NIP-40 is advisory and MUST NOT be relied on for enforcement.** A relay may
  honour it, ignore it, or serve the event long after it has lapsed.
- Expiry is enforced by the receiver against **the rumor's own timestamp**, which
  is the one covered by the seal signature and therefore attributable to the
  sending burner.
- Session-window tests compare that timestamp against the session's ten-minute
  lifetime with a tolerance of **`SLACK = 120` seconds** at each end. `SLACK` is
  normative: if one client accepts what another rejects, honest pairings fail
  between them.
- A rumor whose timestamp falls outside that widened window MUST be **discarded
  from the session entirely** — never shown, never given a nonce exchange, never
  in the SAS candidate list, and not merely excluded from the §13 counter.

**Attribution check (T5).** The rumor's `pubkey` field MUST be set to the sending
burner and MUST equal the key that signed the seal; a rumor failing either test is
discarded. The sending burner appears in no other field.

### 11.5 Relay subscription

The receiving side subscribes:

```
{"kinds":[1059], "#p":["<own burner hex>"], "since": <session start − SLACK>}
```

Dedupe by event id.

**Publishing is parallel, not serial.** A client publishes each message to every
relay from the QR that it has an open socket to. If every relay rejects a publish
(allowlist, paid, unknown key), the client falls back to the local path.

**Clients MUST keep a session outbox.** Every message published during a session
is retained until the session ends, and republished to each relay (a) when a
socket to it opens, and (b) after a NIP-42 authentication with it succeeds. A
relay may accept a socket, receive a publish, and only then demand `AUTH`, leaving
the event discarded on a relay the peer is subscribed to. Recipients dedupe by
event id, so replay is free.

If a relay returns `auth-required`, the client authenticates with its **burner**
under NIP-42. Neither side ever uses a long-lived identity for relay
authentication during a transfer.

### 11.6 Size

Measured expansion from raw payload to published event is **×3.4 for base64
payloads and ×4.7 for hex**.

| Limit | Where | Max payload (base64) |
|---|---|---|
| `max_content_length` = 8196 | NIP-11's example value | 2 082 B |
| `maxEventSize` = 65536 | strfry's default | 21 282 B |
| `maxWebsocketPayloadSize` = 131072 | strfry's default | 30 498 B |

`max_content_length` caps the `content` field alone, which is where the entire
nested ciphertext sits, and is the origin of the 2048 B default in P1. Note that
8196 is the *example* value printed in NIP-11 rather than a measured default;
strfry's stock configuration sets no content cap, and deployed enforcement is
unmeasured.

Clients MUST read `max_message_length` and `max_content_length` from NIP-11 during
the §11.3 probe and skip relays that cannot carry the declared profile's maximum.

### 11.7 Local network path

- The listening party opens a WebSocket on a random port ≥ 49152 and advertises
  `_qrst._tcp` with TXT `npub=<burner npub>`.
- The other party connects and sends the wrap as a single text frame containing
  the kind 1059 event JSON.
- Same messages, seal, wrap, SAS, and cleanup as the relay path. The LAN is
  untrusted; the wrap already assumes that.

Browsers cannot use this path in either role.

## 12. Pairing without a camera

Wherever a flow says "scan the QR", the scanning party MAY instead obtain the same
URI by one of the substitutions below. Each replaces only the pairing step:
burners, SAS, messages, consent and cleanup are unchanged. The URI is not secret
(§15).

### 12.1 Copying the URI

The showing party offers its URI as selectable text; the other party pastes it.

- **Clients MUST accept either form:** a bare `qrst://` URI, or an `https` link
  per §11.2a from which the URI is read out of the fragment.
- **Clients SHOULD offer `qrst://` for copying.** It is shorter and does not
  present as something to tap.
- The URI MUST be validated before use; the bech32 checksum on the burner key
  catches transcription errors.
- **Additional friction for URIs that make the local device the Sender.** Where a
  URI would make the local device the Sender (`mode=offer`) and did not come from
  the device's own camera, the client MUST present the release consent of §9 with
  an explicit statement that the request did not originate from a scan, and MUST
  NOT allow that consent to be remembered or defaulted.

Sending the URI through a third party is permitted; it leaks the metadata that a
pairing happened and which relays are involved, which is a further reason the URI
must never carry payload material.

### 12.2 Channels this specification does not define

A burner key is 32 bytes, so a code-based pairing cannot convey one — it must
bootstrap a channel from a low-entropy shared secret, which requires a
password-authenticated key exchange and a rendezvous that neither party conveys.
That is a different protocol and is not specified here.

An implementation MAY build one. It hands off at a defined point: once both
parties hold the other's burner public key and the parameters of §11.2, Flow A or
Flow B proceeds unchanged from immediately after the scan, and every requirement
of §6 and §9 applies as written. Two clients implementing different bootstrapping
channels will not pair.

## 13. Multiple responders

If, within one session, the receiving side sees messages from **two or more
distinct burner public keys** — two HELLOs in Flow A, two REQUESTs in Flow B — the
client shows a soft, non-blocking notice on the device that displayed the QR:

> Another device also responded to this code. If that wasn't you, someone nearby
> may have scanned it. Nothing was shared with them.

The session continues normally. The SAS comparison decides which responder is
real; the notice is recorded in the transfer event (§14) with the
multiple-responder flag set.

The following MUST NOT count as a second responder: the same message delivered by
more than one route; retransmissions from the same burner; a message that fails to
decrypt; and messages discarded by the session-window test of §11.4.

## 14. Policy

- Any party holding a secret MAY act as Sender, subject to profile restrictions
  (§5).
- A party that received a secret by transfer defaults to **receive-only**. The
  toggle is one action, unguarded, and the transfer screen shows it inline ("This
  device is receive-only — allow sending?") rather than hiding it.
- **Enabling sending MUST expire.** It authorises the transfer at hand, or a
  bounded period the user is shown, and then reverts. It MUST NOT be a permanent
  setting.
- Every transfer MUST write a local record: timestamp, profile, transport, SAS,
  peer burner, and the multiple-responder flag.
- This mechanism has no remote revocation. A device list, if shown, MUST label
  removal as deleting the local copy only.

## 15. Security properties and residual risks

- The transport never sees plaintext payload material.
- A photographed or substituted QR yields nothing on its own: it carries a public
  key; the SAS is commit-then-reveal, so an attacker in the middle cannot grind a
  match; the Sender releases only after verifying the SAS locally; and the
  Receiver accepts only after the user selects the matching SAS and confirms the
  P5 rendering.
- **A hostile party acting as Receiver is not stopped by the SAS.** Such a party
  holds a real burner, receives the real messages, and displays a matching code.
  It is stopped only by a user declining the release prompt of §9. This is the
  mechanism's principal residual risk. Implementations MUST document it and MUST
  NOT describe the SAS as protecting against it.
- **A Receiver may be hostile conditionally.** A web origin serves whatever code
  it chooses to whichever visitor it chooses, so a site's good standing carries no
  information about how it will behave toward one particular user. The structural
  answer is not to give such a party a usable secret: a profile whose payload is a
  threshold share rather than a whole key converts permanent silent theft into
  bounded, revocable use. The loss is not repairable after the fact — splitting a
  key does not change it — so such protections must be in place before the first
  release.
- **Pairing by copied URI widens the delivery channel for that risk**, since a URI
  can be sent in a message while a QR must be placed in front of the user. §12.1
  requires extra friction on the direction where this matters.
- **An operator sees both halves of a session.** T4 covers unlinkability to
  long-lived identity only. A relay carrying both parties observes a subscription
  for one burner and wraps addressed to the other, seconds apart, and can pair
  them. Nothing in this specification prevents that; the burners it links are
  ephemeral and carry no identity.
- Burners are per-session and destroyed, so a session cannot be linked to a
  long-lived identity by the transport — provided the same infrastructure is not
  also carrying that identity's other traffic in a correlatable way.
- P2's single-message rule keeps a transfer indistinguishable from ordinary
  encrypted traffic; a burst of sequenced messages between two keys that have
  never spoken before is not.
- The offline fallback (§10) forfeits every transport property; its security is
  the passphrase and the physical proximity of the two screens.
- Availability comes from the interchangeability of operators, not from any one of
  them. This is deployment advice, not a conformance requirement.
- A compromised device yields whatever that device holds.

## Appendix A — References

NIP-11, NIP-40, NIP-42, NIP-44, NIP-49, NIP-59. BIP-340. ZRTP (RFC 6189), the
source of the commit-then-reveal construction of §6, by way of Matrix.

## Status

Version 1.1-draft. Two things are missing: the event kinds of §11.4 are
unregistered placeholders and will change, and the test vectors are incomplete —
the SAS of §6 is covered in `vectors/`, but the one at the declared payload
maximum that P1 requires is not.

Implementation has begun. Review is more useful than deployment at this stage.
