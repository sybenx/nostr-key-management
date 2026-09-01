# Split plan: transfer primitive vs. key storage

Working document. Proposes splitting `NOSTR_KEY_MANAGEMENT.md` (v8.0-rc1) into
two specifications, with the transfer half written as a generic secret carrier
rather than an nsec-specific one. Nothing here is decided; this is the mapping
and the cost estimate.

## Three layers, not two

The material separates into three layers, not two. Naming them is what makes
the packaging question answerable.

| Layer | Content | Depends on |
|---|---|---|
| **1. Mechanism** | Payload rules, session, commit-reveal SAS, Flow A/B, consent and confirmation requirements, offline fallback, pairing code | Nothing. A transport meeting the contract below |
| **2. Nostr binding** | Gift wrap and seal, NIP-44, event kinds, relay subscription, QR URI syntax, transport selection, LAN path | Nostr. Not FROST, not keys |
| **3. Key management** | Storage ladder, backup, device roles, FROST threshold signing, the nsec and share profiles | Nostr *and* Nostr key semantics |

Layer 2 is the one in question. It is payload-agnostic — it does not know or
care that a key is moving — but it is entirely Nostr. Putting it inside the
FROST document means anyone wanting QR transfer over Nostr for an unrelated
secret has to extract it from a key-management specification, which is the
coupling this split exists to remove.

Three ways to package it:

- **(a) Layers 1+2 in Doc A, layer 3 in Doc B.** Two documents. Doc A is
  complete and implementable standing alone, with the binding as a clearly
  numbered section a reader can see is replaceable. Adopters read one document.
  The seam is visible rather than asserted.
- **(b) Three documents,** one per layer. Cleanest layering, most faithful to
  "the mechanism is independent," but an adopter needs two documents before
  writing any code, and layer 2 alone is too thin to stand as a publication.
- **(c) Layer 1 in Doc A, layers 2+3 in Doc B.** Two documents, but the general
  Nostr binding is stranded inside a FROST specification. Not recommended for
  the reason above.

Recommendation: **(a)**. It gives the mechanism a visible seam without asking a
reader to assemble a protocol from two files, and a NIP submission is then
exactly Doc A rather than a stapling of two.

## Document order: requirements first, Nostr second

Both new sections below (T1–T8, P1–P7) are written **before** Nostr is
mentioned, and the Nostr binding then appears as *one substrate that satisfies
them* rather than as the premise. This is not only presentation. It makes the
choice of Nostr falsifiable: with the contract written down, someone can later
check each thing NIP-59 mandates against the list and ask whether it is load-
bearing or merely inherited. If parts of gift wrap turn out not to be required
by T1–T8, either a simpler construction exists or another substrate qualifies
more cheaply. If every requirement traces to a clause, Nostr is the floor and
that question is closed.

Writing it the other way round — Nostr first, requirements extracted afterwards
— would make the list unfalsifiable, because it would be a description of what
Nostr happens to do rather than a statement of what the mechanism needs.

## The mailbox framing

Recommended explanatory device for Doc A §1, because it carries T1 and T2 in one
sentence to a reader who has never heard of a relay:

> The QR is a mailbox address, plus which postal system to use. The mailbox is
> created for this one exchange and destroyed when it ends. The post office
> cannot read the mail, cannot tell who sent it, and did not ask anyone to
> register.

What makes this QR *transfer* rather than any other QR is precisely that the
code encodes an address at which the showing device can be reached, not the
secret itself. A QR containing the secret is a different and worse thing — it is
the off-grid fallback, and it is why that fallback needs its own passphrase
encryption (P7).

Two cautions when using the analogy in normative text: the size ceiling is a
property of the postal system, not the address, and it does not change once
addresses have been exchanged (see P2); and the mailbox is not a channel that
stays open — the session ends and the burners are destroyed.

## Transport requirements

The claim "Nostr could be removed and replaced and the mechanism would still
function" is only checkable if the document says what a replacement would have
to provide. Stating this contract is what turns that claim from aspiration into
a property, and it is the natural companion to the payload requirements below.

A conforming transport MUST provide:

- **T1 — Ephemeral addressing.** A party can be addressed at a freshly
  generated public key with no prior registration of that key.
- **T2 — No account.** Neither party holds an identity, credential, or
  relationship with the transport operator. Nothing is provisioned to start a
  session.
- **T3 — Confidentiality.** Message contents are unreadable by the operator and
  by third parties.
- **T4 — Unlinkability.** A session cannot be linked by the operator to either
  party's long-term identity, and the two parties of a session cannot be linked
  to each other by an observer.
- **T5 — Capacity.** Carries at least the maximum payload of P1 in a single
  message.
- **T6 — Untrusted operator.** The operator can drop and observe messages but
  cannot forge or substitute them undetected. Substitution is the SAS's job;
  the transport must not need to be honest for confidentiality to hold.
- **T7 — Expiry.** Messages can be given a bounded lifetime.
- **T8 — Liveness within the session.** Best-effort delivery inside the
  ten-minute session window. No ordering guarantee is required beyond what the
  flow itself enforces.

The Nostr binding satisfies these with gift wrap (T3, T4, T6), burner keypairs
(T1, T2), NIP-40 expiration (T7), and public relays (T2, T8). T5 is quantified in P1. **Availability note:** relay interchangeability — many
equivalent operators, none of them yours — is not a requirement of the
mechanism but is the property that makes the whole approach practical, and
belongs in the security and rationale text rather than here.

## Payload requirements

Today the payload is always 32 bytes, so the specification never states a single
constraint on it. Making it arbitrary means stating all of them. These are what
a payload must satisfy for the transport to work; everything else about it is
the profile's business and the carrier's ignorance.

**P1 — Bounded size.** One payload, one gift wrap. Computed, not estimated;
`payload_ceiling.py` reproduces every number here.

The secret is nested three times — rumor, then seal, then wrap — and each layer
base64-expands and pads. Net cost is **3.4× for base64 payloads, 4.7× for hex**.
An nsec is 1.9 KB on the wire; a 4 KiB payload is ~14 KB.

Relay limits, not NIP-44, set the real ceiling, and there are two of them:

| Relay limit | Source | Max payload (base64) | Max payload (hex) |
|---|---|---|---|
| `max_content_length` = 8196 | NIP-11's own example value | **2 082 B** | 1 388 B |
| `maxEventSize` = 65536 | strfry default | 21 282 B | 14 188 B |
| `maxWebsocketPayloadSize` = 131072 | strfry default | 30 498 B | 20 332 B |

`max_content_length` is the trap. It caps the `content` field alone, which is
where the entire nested ciphertext sits, and it binds an order of magnitude
tighter than event size. A 4 KiB payload needs 13 744 content characters and
fails outright against the 8196 example value.

**The document should publish the tiers, not a single number, and let the
implementer choose reach against capacity.** Proposed normative text:

- **2048 bytes, base64 — RECOMMENDED default.** Content 6 916, wrap event
  7 361. Clears every limit above, including relays advertising the tightest
  commonly-cited content cap. Choose this to reach essentially all relays.
- **Up to 21 KiB** — reaches relays with a 64 KiB event limit and no content
  cap (strfry's default configuration). Fewer relays, more data.
- **Above that** — a small minority of relays. Specify it, do not recommend it.

A profile MUST declare which tier it requires. Implementers pick the tradeoff;
the specification names the consequences and does not choose for them.

*Honest caveat to carry into the text:* 8196 is the **example** value printed in
NIP-11, not a measured default — strfry's stock config sets no content cap at
all. How many deployed relays actually advertise and enforce one is unmeasured.
That uncertainty is itself the argument for tiers over a single number.

The test vector MUST sit at exactly the chosen ceiling. NIP-44 pads to
power-of-two-derived chunks, so an off-by-one-chunk error is invisible for every
payload except those near a boundary — precisely where nobody tests.

**Binding-level addition.** §3.1 already probes relays before showing transfer
UI. That probe SHOULD also read `max_message_length` **and
`max_content_length`** from NIP-11 where advertised, and skip relays that cannot
carry the declared profile's tier. Today a client learns this from a rejected
publish, inside a three-second transport selection.

**P2 — Single-shot. One payload, one session.** Chunking, fragmentation and
resumption are not merely unspecified — a conforming implementation MUST NOT
attempt them over public relays. Three reasons, and the document should give all
three, because "not yet specified" invites someone to specify it.

*Operational.* Relays are not obliged to carry anyone's traffic. A client that
pushes a burst of large wraps gets rate-limited, then IP-blocked, and the block
lands on gift wraps generally — which is to say on other people's direct
messages, not just on the offender's transfers. The mechanism does not get to
externalise its costs onto infrastructure nobody is paying for.

*Anonymity set.* A single small kind-1059 wrap is indistinguishable from an
ordinary NIP-17 direct message, which is the whole reason T4 holds in practice:
the transfer hides in ordinary traffic. A burst of twenty sequenced wraps
between two keys that have never spoken before does not look like a
conversation, and an observer who can pick the transfer out of the crowd has
recovered exactly what gift wrap was chosen to deny.

*Definitional.* T2 and P1 are the same constraint seen from two sides. The
mechanism may use infrastructure it does not own, pay for, or register with
precisely because it asks almost nothing of that infrastructure. Asking more
forfeits the property that makes the approach interesting.

The escape hatch is legitimate and should be stated as such: **if you need to
move large data this way, run your own relay.** That is a supported deployment
and nothing in the mechanism forbids it. But it is a different proposition —
the moment capacity requires a relay you operate, the claim collapses from
"public infrastructure nobody runs for you" back to ordinary
client-and-server, which is the thing this exists to avoid. The specification
should say that plainly rather than presenting self-hosting as a scaling tier.

*What it would take, for the record.* Were multi-message transfer ever
specified for a self-hosted deployment, it would need chunk ordering, a
completeness check, integrity over the reassembled whole so a relay cannot
silently drop one chunk, and a session lifetime beyond ten minutes. Recording
this prevents the gap being filled incompatibly by implementers who assume it
was an oversight.

*Related misreading to pre-empt.* The ceiling is a per-message transport limit,
not a QR limit, and the handshake does not lift it. The QR only ever carried a
public key; P1 binds every message crossing a relay, before and after the
mailbox exchange alike.

**P3 — Opaque to the carrier.** The transport MUST NOT parse, validate, or
depend on the structure of the payload. This is what makes the tool ambivalent,
and it is a MUST NOT rather than a nicety: a carrier that peeks acquires a
version-compatibility problem with every profile.

**P4 — Identifiable against the declared profile.** The receiver MUST be able to
determine that what it unsealed belongs to the profile declared in the QR, and
MUST abort otherwise. Without this, an application supporting several profiles
can be steered into accepting a type the user did not intend. The check itself
is defined by the profile; the requirement to have one is Doc A's.

**P5 — Renderable to a human.** The profile MUST be able to render the received
payload as something a user can recognise before it is committed to storage. See
rewrite item 1: this is load-bearing against login-substitution, not cosmetic. A
payload that cannot be meaningfully summarised to its recipient MUST NOT use
this transport.

**P6 — Safe to hold and discard.** A receiver may hold several candidate
payloads simultaneously (§3.8, and the five-pending cap in Flow B) and commits
at most one. A payload must tolerate being received, held in memory, and wiped
without side effects. With P1 raised to kilobytes, the pending cap is now also a
memory bound and should be stated as one.

**P7 — Confidentiality comes from the transport, except offline.** A payload
need not encrypt itself: the seal and wrap already do. The exception is the
offline QR fallback, which has no transport encryption at all — a profile that
permits offline transfer MUST define its own passphrase-based encryption for it.
This is what NIP-49 is doing in the current §6, and generalising it is what
turns that from a special case into a rule.

## Why the split works

Dependency between the two halves is close to one-directional.

**Transfer → storage/threshold** is four hooks, all of which a transfer
specification should not have been defining anyway:

| Hook | Current location | Belongs to |
|---|---|---|
| `mode=server`, `url=` in the QR URI | §3.2 | §11.2 server enrolment |
| `enrol` tag on KEY_REQUEST, TRANSFER_ACK | §3.4 | §11.1 device list |
| `lock` tag on KEY_TRANSFER | §3.4 | §2.2 unlock policy |
| "store nsec (§2.1)" | §4 step 15, §5 step 16, §6 step 3 | §2.1 storage ladder |

**Storage/threshold → transfer** is heavy: §11.2, §11.7, §11.8 and §11.15 all
ride the transfer flow. That is the correct direction — Doc B builds on Doc A,
not the reverse.

**The case for a generic carrier is already in the text.** §11.7 runs "Flows
A/B unchanged through the SAS step" and then substitutes `KEY_SHARE_PART` for
`KEY_TRANSFER`. The specification already treats the handshake as a
payload-agnostic carrier without saying so. Making that explicit turns §11.7
from a special case into the second consumer of a documented extension point,
and makes the README's "relay information, and other secrets" claim true
instead of aspirational.

## Two incidental reasons to do it now

- Event kinds 24301–24315 are unregistered placeholders. Splitting them into
  two contiguous ranges is free today and expensive after anyone implements.
- Renumbering breaks section citations in `SPEC_ISSUES.md`, which currently
  holds exactly one open entry. That cost only rises.

---

## Doc A — `QR_SECRET_TRANSFER.md`

Standalone and publishable on its own. Outline assumes packaging (a) — layers 1
and 2 together, with §3 stating the transport contract and §11 being the one
Nostr-dependent section. Under (b), §11 becomes its own document and §§0–10 and
12–15 are unchanged. Under (c), §11 moves into Doc B and Doc A is not
implementable alone.

Sections 6–10 are written against the transport contract, not against gift wrap:
they say "send HELLO to the peer," and §11 says what that is on Nostr.

| New § | Source | Action |
|---|---|---|
| 0. Design principle | §0 | Rewrite — restate the degradation rule for transport only |
| 1. Overview | §1 | New prose, built on the mailbox framing below. "An identity is an nsec" goes to Doc B |
| 2. Definitions | §3 | Move. `Sender` / `Receiver`; see rewrite item 8 |
| 3. Transport contract | — | **New.** T1–T8 above |
| 4. Payload requirements | — | **New.** P1–P7 above |
| 5. Profiles | — | **New.** Extension point, plus one non-normative worked example |
| 6. Session and SAS | §3.3 | Move verbatim |
| 7. Flow A | §4 | Rewrite steps 14–16; abstract the message vocabulary |
| 8. Flow B | §5 | Rewrite steps 5, 16; abstract the message vocabulary |
| 9. Consent and confirmation | §4 prose, §8 | **New section** assembling requirements now scattered in prose |
| 10. Offline QR fallback | §6 | Substantial rewrite — see rewrite item 2 |
| 11. Transport binding: Nostr | §3.1, §3.2, §3.4, §3.5, §3.6 | **The only Nostr-dependent section.** Consolidate all of it here |
| 12. Pairing without a camera | §3.7 | **Restructured.** 12.1 copy the URI (new, RECOMMENDED where a clipboard spans both devices); 12.2 the SPAKE2 pairing code, now OPTIONAL |
| 13. Multiple responders | §3.8 | Move verbatim |
| 14. Policy | §8 (part) | Receive-only default, `transfer_event` log |
| 15. Security properties | §9 (part) | Move the transfer bullets, state them more prominently |
| Appendix A | Appendix A | Move (still missing the table) |

## Doc B — `NOSTR_KEY_STORAGE.md`

Cites Doc A the way it cites NIP-59 and NIP-44: an external protocol it uses,
not a companion volume. Doc B is as Nostr-specific as it already is; no attempt
to genericise anything here.

| New § | Source | Action |
|---|---|---|
| 0. Design principle | §0 | Restate for feature degradation |
| 1. Overview | §1 | Keep the "an identity is an nsec" framing |
| 2. Storage | §2.1–2.4 | Move verbatim |
| 3. Backup | §7 | Move verbatim |
| 4. Device roles and policy | §8 (part), §11.1 | Trusted/restricted is a threshold concept, not a transfer one |
| 5. Server: backup and threshold | §11 | Move; replace inline flow descriptions with references to Doc A |
| 6. Profile: Nostr nsec | §3.4, §4 | **New.** Registered against Doc A §5 |
| 7. Profile: FROST share issuance | §11.7 | Rewrite as a second registration |
| 8. Security properties | §9 (part) | Move the storage and threshold bullets |
| 9. Out of scope | §10 | Move verbatim |

**What "references it as a tool" means concretely.** §11.2, §11.7, §11.8 and
§11.15 currently describe transfer mechanics inline. Each becomes a citation:
"the device and the server run [QR Transfer] Flow A under profile
`frost-share`, and on completion the Receiver holds …". Doc B stops restating
burners, SAS, and wraps entirely. §11.7's "Flows A/B run unchanged through the
SAS step" is the sentence that becomes unnecessary — under the split, that is
simply what using the protocol means.

## Passages needing real rewriting

Everything not listed here is relocation. These are the seven places where
genericizing changes meaning, ordered by risk.

### 1. Flow A steps 14–16 — highest risk

Current text: the Receiver "derives npub, shows *Log in as @name?*" before
storing. §4's closing note establishes that this is not cosmetic — steps 14–15
are the defence against login-substitution, where someone who photographed the
QR races the real Sender and plants their own key.

Genericizing cannot weaken that. The replacement must be a normative
requirement *on profiles*, not a deletion:

> A profile MUST define a human-meaningful rendering of the received payload,
> shown to the user for confirmation before the payload is committed to
> storage. The Receiver MUST NOT commit a payload before the user has both
> selected the matching SAS and confirmed that rendering. A profile that cannot
> render its payload meaningfully MUST NOT use this transport.

The nsec profile in Doc B then supplies "derive npub, show `Log in as @name?`"
as its rendering. Any profile that skips this reintroduces the attack, so the
requirement has to be stated as a MUST in Doc A §5, not left implicit.

Because the nsec profile now lives in Doc B, Doc A §5 must carry a
**non-normative** worked example instead. Without one, Doc A is unreviewable:
no reader can check that the extension point is sufficient, and no
implementation can be tested end to end against Doc A alone.

### 2. §6 off-grid transfer

Two independent problems.

`ncryptsec` (NIP-49) is a key-encryption format — a generic document cannot
mandate it. Becomes: profiles MAY define a passphrase-encrypted offline QR
encoding; the nsec profile specifies NIP-49 with `log_n = 18`, KSB `0x02`.

Separately, the paragraph beginning "In threshold mode, off-grid transfer is
unavailable toward restricted targets" is a §11 policy written inside a
transfer section. It cannot be a tag passthrough. Doc A needs an explicit hook:

> A profile MAY restrict which parties are permitted to act as Sender, and MAY
> disallow the offline fallback entirely.

Doc B then states the keep-key restriction against that hook. This is the only
genuine two-way entanglement in the whole document.

### 3. §3.4 message kinds

Rename away from key vocabulary (`KEY_HELLO` → `XFER_HELLO`, `KEY_TRANSFER` →
`XFER_PAYLOAD`). `KEY_TRANSFER.content` stops being "64 lowercase hex chars:
the 32-byte private scalar" and becomes an opaque profile-defined string.

Add the passthrough rule that makes the four hooks in the table above work
without Doc A knowing what they mean:

> A profile MAY add tags to any rumor. Implementations MUST ignore tags they do
> not recognise. Profile tags MUST NOT collide with `burner`, `commit`,
> `nonce`, or `v`.

`enrol` and `lock` then become nsec-profile tags with no change to their
current wire format.

### 4. §3.2 QR URI

`mode` becomes an extensible registry (`offer`, `request`, plus
profile-registered values); `url=` moves to Doc B as part of the `server` mode
registration. `plat`/`origin` and the unverified-claim paragraph stay in Doc A —
they are transport-level and the consent prompt depends on them.

A required `p=<profile-id>` parameter is added (decision 2 below). `mode` states
who is showing the QR; `p` states which profile the transfer is under. The
receiving side MUST abort if the payload it unseals does not match the `p` it
agreed to, and either side MUST abort at scan time if it does not implement the
declared profile — before any burner is generated.

### 5. §8 transfer policy

Splits. "Any device holding the secret MAY act as Sender," the receive-only
default, and the `transfer_event` log are Doc A. Trusted/restricted roles are a
threshold concept and go to Doc B §4 — including the "Trust this device"
checkbox, which Doc A should describe only as a profile-supplied element of the
consent prompt.

### 6. §9 security properties

Splits along the same line. The three transfer bullets — relays never see
plaintext, a photographed QR yields nothing, a phishing Joiner is stopped only
by the consent prompt — are Doc A and should be stated more prominently there
than they are here, since they are the entire claim of the document.

### 7. §0 and §1

Both need writing fresh rather than cutting. Doc A's design principle is about
transport degradation (relay → LAN → offline QR); Doc B's is about feature
degradation (level 3 → level 1 storage, threshold → base). Currently one
paragraph does both jobs.

### 8. Terminology rename, both documents

`Holder` → `Sender`, `Joiner` → `Receiver` throughout: both flow diagrams, every
§11 cross-reference, the rumor descriptions in §3.4.

**Roles are named by what a party does with the secret, never by who shows the
QR.** In Flow A the Receiver shows it; in Flow B the Sender does. Any naming
keyed to the QR (`QR provider` / `Mailer`, or `Q` / `M`) would denote opposite
parties in adjacent sections. This is not a stylistic preference — it is why the
specification separates the payload role from the flow in the first place.

**Notation costs nothing on the wire.** `S.pub` versus `SND.pub` exists only in
this document's prose and diagrams; the QR carries a bech32 key and URL
parameters regardless. Abbreviating for data savings saves no data. The one
place QR bytes are genuinely spendable is the parameter set — keep profile IDs
short — and even there, against a 63-character npub and up to four relay URLs,
fifteen characters is not the constraint.

**The collision to resolve.** Doc B uses `S.pub` for the server's enrolment key
(§11.2, §11.6, §11.8). §11.7 involves a server and a sender in the same
paragraph, sending different material to the same device.

1. Doc A uses `SND` / `RCV`. Unambiguous; Doc B untouched. *Recommended.*
2. Doc A uses `S` / `R`, Doc B renames the server key to `SRV.pub`. Cleaner
   diagrams; edits more of §11 than the split otherwise requires.

Do not ship `S` meaning both.

---

## Fix §3.1 during the split

The one open `SPEC_ISSUES.md` entry — a browser Sender whose relay probe times
out has no transport at all — lands entirely inside Doc A, in what will be its
§3. Publishing a new standalone specification carrying a known, already-written
defect is worse than publishing it fixed. The proposed replacement text in that
entry is ready to apply.

## Housekeeping

- **Kind ranges.** Doc A takes seven contiguous kinds; Doc B takes its own
  range. Both stay marked as placeholders.
- **`SPEC_ISSUES.md`.** Keep one file for both documents and add a
  **Document:** field to the entry format, rather than maintaining two issue
  trackers. The existing entry needs its section numbers updated.
- **`OVERVIEW.md`.** Currently covers both halves. Either split it too or keep
  it as the combined reader's introduction pointing at both — the latter is
  less work and arguably more useful.
- **`README.md`.** Becomes an index for two documents. Also carries the three
  unsupported claims noted separately (Bluetooth transport, transferable relay
  information, shoulder-surfing as the headline property); the second of these
  becomes true once Doc A §4 and §5 exist.

## Decisions

1. **Rename `Holder`/`Joiner` to `Sender`/`Receiver`, abbreviated `SND`/`RCV`.**
   Settled. Doc B keeps `S.pub` for the server, so the two documents stay
   unambiguous while being closely intertwined.

2. **Add a `p=<profile-id>` parameter to the QR URI.** Accepted. What is being
   transferred must be declared, not inferred. Without it, `mode` carries the payload type only implicitly:
   both sides run the full handshake — burners, nonces, SAS comparison, two
   user confirmations — and learn what was actually sent only when the final
   wrap is unsealed. That means an application supporting one profile cannot
   decline at scan time, the Sender's consent prompt cannot honestly name what
   it is about to send, and an application supporting several profiles has
   nothing declared up front to check the arriving payload against. Cost is one
   QR parameter and one abort case.

3. **The nsec profile lives in Doc B, not Doc A.** Settled. Doc A stays
   payload-agnostic. The consequence is that Doc A needs a non-normative worked
   example in Doc A §5 (see rewrite item 1), otherwise the extension point cannot be
   reviewed and no implementation can be tested against Doc A standing alone.

4. **Where the Nostr binding lives.** Resolved — option (a). Layers 1 and 2 in
   Doc A, the binding as its own numbered section (§11). Settled regardless: the mechanism layer is written against
   the transport contract (T1–T8), not against gift wrap, which means both flow
   diagrams are rewritten rather than moved. That is the cost of the mechanism
   being genuinely separable instead of merely described as such.

5a. **SAS encoding.** Resolved. Emoji are the primary comparison; digits are
   widened to eight and shown alongside for screen-reader access and as the
   fallback when bundled glyphs cannot render. Either may be compared alone —
   24 and 26.6 bits respectively, both above the ~20-bit practical floor set by
   user-retry behaviour rather than by the single guess. `EMOJI_TABLE` closed by
   normative reference to Matrix's 64-entry Apache-2.0 set at a pinned commit,
   rendered from a **bundled** OFL font (Noto Emoji, monochrome subset
   recommended) rather than the platform's, which removes vendor divergence at
   the source instead of mitigating it. Table and glyphs are frozen on ship;
   a revision is a protocol version change.

5. **Payload size ceiling.** Resolved as tiers rather than a number — see P1.
   Recommended default 2048 B base64; 21 KiB and above documented as
   reach-reducing choices. Reproducible via `payload_ceiling.py`.

6. **§3.7 is demoted, not removed.** Copying the URI covers the no-camera case
   wherever a clipboard spans both devices, and the URI is not secret, so the
   substitution is sound with no change to burners, SAS or consent. The pairing
   code remains for two camera-less machines that share no clipboard, and for
   codes read aloud — cases where the alternative is transcribing 200 characters
   by hand. It becomes OPTIONAL, which is proportionate: SPAKE2, HKDF,
   confirmation MACs, both PGP word lists and a 1000-value rendezvous space is
   the most expensive section in the document.

   Two things this raised that the original proposal did not. Copying does **not**
   require moving to `https` — plain URI text pastes fine, and `https` would cost
   a domain the implementer operates and serves an association file from, which
   is a server dependency in a specification premised on having none. And a
   pasted URI is *remotely deliverable* where a QR is not, which widens the
   delivery channel for the §9 hostile-Receiver risk from physical presence to a
   message; §12.1 therefore requires extra friction on a pasted URI that makes
   the local device the Sender, and §15 records the widening.
