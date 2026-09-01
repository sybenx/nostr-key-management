# Implementation Proposal

**Status:** proposal, not yet agreed. Nothing here is normative; where this
document and `NOSTR_KEY_MANAGEMENT.md` disagree, the specification wins.

This proposes how the specification becomes code that a site or an app can
adopt in three lines, what that code cannot honestly promise, how the
repository should be laid out to hold both, and in what order to build it.

---

## 1. What can be a drop-in, and what cannot

The specification is two products stacked, and they have very different
adoption stories. Saying so plainly up front is what keeps the library's
README from over-promising later.

**§1–§8 can genuinely be dropped in.** The storage ladder, the burner
handshake, the SAS, gift-wrapped transfer over relays, and `ncryptsec` export
are all self-contained client code. A site adds a script tag and gets a key
onto the device under the specification's rules, with no infrastructure behind
it and nothing for the operator to run. This is the part that should ship
first and be marketed as the whole product.

**§11 cannot be a single drop-in, ever.** FROST at `t = 2` with index 1 held by
the server is not a client feature; it is a distributed system. A package that
implements the device half is inert without a server to point at, so §11 is two
deliverables — a client and a reference server — and the honest framing is "run
this, then enable that," not "install this."

**Native apps are a third thing.** A JavaScript package cannot serve the iOS
and Android clients the specification is largely written for, and hand-writing
Swift and Kotlin ports triples the review surface. The realistic answer is one
canonical TypeScript implementation plus a conformance vector suite that ports
validate against — which is also how the missing test vectors get produced (§7).

---

## 2. The integration surface

Three tiers, each a superset of the one above. Most adopters should never see
tier 2.

### Tier 0 — script tag

```html
<script src="https://unpkg.com/nostr-keyxfer-login"
        data-relays="wss://relay.damus.io,wss://nos.lol"
        data-app-name="Zapstr"></script>
```

Sets `window.nostr` to a NIP-07 signer and dispatches a `nkxAuth` event on
login and logout. An existing Nostr site that already talks to `window.nostr`
integrates by adding this line and deleting nothing. This is deliberately the
same shape as `nostr-login`, because that shape is already proven and a site
evaluating both should not have to restructure to try ours.

### Tier 1 — the module API

```ts
import { NostrKeys } from '@keyxfer/web'

const keys = await NostrKeys.open({
  relays: ['wss://relay.damus.io'],
  appName: 'Zapstr',
})

if (keys.status === 'empty') {
  await keys.login()        // draws the QR, runs §4, resolves once stored
}

const pubkey = await keys.signer.getPublicKey()
const event  = await keys.signer.signEvent(draft)
const ct     = await keys.signer.nip44.encrypt(peer, 'hi')
```

`keys.signer` satisfies NIP-07 exactly, so `window.nostr = keys.signer` is a
valid line of user code and every existing library keeps working. `keys.login()`
is Flow A (§4) — the browser is always the Joiner showing the QR, because a
browser cannot scan reliably and, per §11.1, is always `restricted` anyway.

Everything else is progressive disclosure on the same object, and none of it is
required to log in:

```ts
keys.storageLevel                     // 1 | 2 | 3, per §2.1
keys.lock                             // 'device' | 'launch' | `idle:${number}`
keys.export({ password })             // §7.1, always ncryptsec, privileged
keys.backup.connect(url, password)    // §11.2 → §7.2 setup
keys.backup.recover(url, password)    // §11.10 — throws in a browser, by §11.10
keys.devices.list() / .remove(id)     // §11.1, §11.11
keys.threshold.enable() / .disable()  // §11.5, §11.15 — trusted devices only
keys.on('lock', s => …)               // §11.16 states, for the indicator
keys.on('alert', a => …)              // §11.13 digests and alerts
```

Methods a browser may not perform per the specification are present on the type
and reject at runtime with a named error (`RestrictedRoleError`), rather than
being absent. A missing method reads as an incomplete library; a refusal that
cites §11.13 teaches the integrator what the role system is for.

### Tier 2 — headless

```ts
const session = createTransferSession({ role: 'joiner', mode: 'offer', …adapters })
session.qrUri                          // §3.2
session.on('sas', ({ emoji, digits }) => …)
session.confirm() / session.reject()
```

For anyone drawing their own UI: React Native, a desktop app, an embedder who
wants the flow inside their own modal. Same state machine as tier 1 with the
screens removed.

---

## 3. Package layering

The layering exists to serve one goal: **`core` is pure, so a Swift or Kotlin
port has exactly one thing to reimplement and exactly one suite to prove it
against.**

| Package | Contains | Depends on |
|---|---|---|
| `@keyxfer/core` | Every derivation and state machine in the specification, as pure functions over injected randomness and clock. SAS commit/nonce/reveal (§3.3), QR URI parse and build (§3.2), rumor construction and validation (§3.4, §11.17), Flow A/B state machines (§4, §5), SPAKE2 (§3.7), blob-store key schedule (§7.2), FROST wrappers, refresh algebra (§11.9), epoch ordering (§11.4). No I/O, no DOM, no `fetch`, no timers. | `@noble/curves`, `@noble/hashes`, `@scure/base` |
| `@keyxfer/web` | The adapters that make `core` run in a browser: storage per §2.3, relay transport, WebAuthn gate, `navigator.storage.persist()`, camera. Exports `NostrKeys`. | `core` |
| `@keyxfer/ui` | The screens the specification writes copy for: QR, SAS picker with the consent line from §4 step 9, the origin shown as punycode, the lock indicator (§11.16). Framework-free custom elements so it drops into React, Svelte, or nothing. | `web` |
| `nostr-keyxfer-login` | Tier 0. One IIFE bundle, no build step for the adopter, sets `window.nostr`. | `ui` |
| `@keyxfer/server` | The reference blob store (§7.2) and co-signer (§11.6, §11.6a) with the audit rules of §11.13. One codebase, two deployment targets: Cloudflare Worker and Node. | `core` |
| `@keyxfer/vectors` | Generates the normative test vectors from `core`; runs them as a conformance suite any implementation can execute. | `core` |

`core` communicates with its host by returning **commands as data**, never by
calling out:

```ts
type Command =
  | { t: 'publish';  relays: string[]; event: NostrEvent }
  | { t: 'subscribe'; filter: Filter }
  | { t: 'store';    slot: 'nsec' | 'share' | 'E'; bytes: Uint8Array }
  | { t: 'prompt';   kind: 'consent' | 'privileged'; text: string; claims: Claims }
  | { t: 'zeroize';  handle: Handle }
```

Two consequences make this worth the indirection. A test can drive the entire
Flow A ladder with a fake clock and fixed randomness and assert on the exact
byte sequence — which is what a *vector* is. And a native port implements the
adapters in its own language while running the same command trace, so
"interoperable" becomes a thing CI can check rather than a thing two authors
believe.

---

## 4. Repository layout

```
nostr-key-management/
├── README.md                      # pitch, then: the spec is here, the code is there
├── spec/
│   ├── NOSTR_KEY_MANAGEMENT.md
│   ├── OVERVIEW.md
│   ├── SPEC_ISSUES.md
│   └── vectors/                   # generated, committed, referenced normatively
│       ├── sas.json
│       ├── blob-store.json
│       ├── spake2.json
│       ├── ncryptsec.json
│       └── frost.json
├── packages/
│   ├── core/ web/ ui/ login/ server/ vectors/
├── examples/
│   ├── plain-html/                # the three-line integration, verbatim
│   ├── react/
│   └── worker/                    # deploy the reference server in one command
├── pnpm-workspace.yaml
└── .github/workflows/ci.yml       # typecheck, unit, conformance vectors, size budget
```

`git mv` for the three existing documents; every current link is relative and
`spec/` keeps them adjacent, so only `README.md` needs editing.

---

## 5. Does it need a new repo?

**No — keep both here for now, and split later on a stated trigger.**

For keeping them together: the implementation is what *produces* the test
vectors, and a vector that lives in a different repository from the requirement
it tests will drift the first time either side moves quickly. Both are pre-1.0
and will change together often. And there is one author, for whom two
repositories is two release processes, two issue triage habits, and a
cross-repository version matrix, in exchange for tidiness nobody is asking for
yet.

Against, and it is a real cost: a specification with the reference
implementation in the same repository reads as a product's documentation rather
than as a standard, which matters if the goal is other people implementing it
independently. And `SPEC_ISSUES.md` is carefully designed for spec
disagreements, while a library attracts "fails under Vite 7." Handle the second
with issue templates and a `spec:` / `impl:` label pair; the first is genuinely
only solved by splitting.

**Split when all three are true:** the event kinds are registered, the
specification has gone a release without a normative change, and a second
independent implementation exists. At that point `nostr-key-management` keeps
the specification and the vectors, and the packages move to
`nostr-keyxfer-js` — with the vectors consumed as a versioned dependency, which
is the relationship you want by then anyway.

---

## 6. The three gaps, closed by code

`README.md` names three things missing, and says review is more useful than
implementation right now. That is still true of *deployment* and no longer true
of *writing code*, because two of the three gaps can only be closed by writing
it.

**`EMOJI_TABLE` (Appendix A).** Appendix A states constraints and contains no
table, so no two implementations agree. The fix is `packages/core/src/emoji.ts`
as the single source, with a build step that renders it into Appendix A and CI
that fails when the two diverge. Selection needs a real pass against iOS,
Android, Windows and Noto for glyph collisions — that is an afternoon with a
rendering harness, not a research problem, and it should be done once and
frozen.

**Test vectors.** `@keyxfer/vectors` generates them from `core` with fixed
randomness: SAS from `H.pub`/`J.pub`/both nonces through to the four emoji
indices and six digits; the §7.2 ladder from password and salt through
`K_pw`, `K_enc`, `K_auth`, `K_wrap` to a decryptable blob; SPAKE2 transcripts
per RFC 9382; `ncryptsec` at both `log_n` values; and for §11, a full
activation, one refresh, and a joint issuance with the parity case of §11.4
covered explicitly, since odd-y is where an independent implementation will
first diverge.

**Event kinds.** They stay unregistered until the NIP lands, so the mitigation
is containment: one `KINDS` constant module, the `v=1` check already required by
§3.2 enforced at parse time, and a published `0.x` that says in its README that
kinds will change and interoperability is not promised before 1.0. Nothing
should be tagged 1.0 until the kinds are real.

---

## 7. Build order

Each milestone is useful to somebody on its own, which matters when the author
count is one.

**v0.1 — the actual drop-in.** §2 storage ladder with silent probing and
in-place upgrade, §3–§5 transfer both flows over relays, §3.8 multi-responder
notice, §6 off-grid, §7.1 `ncryptsec` export, NIP-07 signer, tier 0 bundle.
No server, no account, nothing to run. Ships the emoji table and the first
three vector files.

**v0.2 — backup.** §7.2 blob store, `@keyxfer/server` on a Worker, §11.10
recovery in a native context only, and the recovery-delay notices (kind 24316).
The server is small and stateless and is the thing that makes §11 credible
later.

**v0.3 — device list.** §11.1 enrolment keys, kind 30242, roles assigned by the
Holder's consent box, per-device settings, §8 transfer events surfaced. Still
no threshold; this is the bookkeeping §11 needs and it has standalone value as
a "where am I logged in" screen.

**v0.4 — threshold.** §11.4–§11.15. The largest step by a wide margin, and the
one that should not start until v0.1–v0.3 have been used by somebody.

**1.0 — when the kinds are registered.**

---

## 8. Risks, stated honestly

**FROST in JavaScript.** There is no established, audited FROST implementation
over BIP-340 in JavaScript. `@noble/curves` provides the curve and Schnorr
primitives, not the threshold protocol. Writing RFC 9591 plus the taproot
parity handling by hand is a reviewable-crypto project with a review budget
attached. The better move is to compile the ciphersuite §11.4 already names —
`frost-secp256k1-tr`, Zcash Foundation, Rust, on crates.io — to WebAssembly
with `wasm-bindgen`, and use it in both browser and Node. That is byte-for-byte
the construction the specification points at, rather than a reimplementation of
it, and it removes the largest single source of interoperability risk. Cost is
a Rust toolchain in the build and a few hundred kilobytes in the §11 bundle,
which is acceptable because §11 is opt-in and lazily loaded.

**scrypt at `log_n = 18` in a browser.** 256 MiB per guess is the point, but
pure-JS scrypt at that size is tens of seconds and may simply fail on mobile
Safari. It needs a WASM scrypt in a worker with progress reporting. §11.10
already forbids browser recovery, which removes most of the exposure, but §7.1
export runs in browsers and the `log_n = 17` allowance for low-memory devices
must be wired to a real capability probe rather than a user-agent guess.

**A browser "device" can silently evaporate.** §2.3 stores `W` in IndexedDB and
calls `navigator.storage.persist()`, but persistence can be declined and
eviction is real. Integrators will report this as data loss. The library should
surface it as an explicit state (`keys.durability`) and the docs should say
plainly that a browser is a device that can disappear, which is precisely why
§11 makes browsers `restricted` and re-enrollable.

**The phishing residual is a library problem too.** §9 is candid that a phishing
page acting as Joiner shows a matching SAS and that only the §4 step 9 consent
line stands against it. That line is UI, and UI is the part adopters most want
to restyle. `@keyxfer/ui` should let integrators theme the frame and refuse to
let them alter, hide, or shorten the claimed-origin line — the consent text is
part of the security argument, not part of the skin.

**Bundle size is an adoption gate.** Tier 0 competes with a script tag people
add casually. Budget: base bundle under 60 KB gzipped with §11 in a separate
async chunk, enforced in CI, or the first bug report is "this doubled my
bundle."

---

## 9. Decisions needed before scaffolding

1. **npm scope.** `@keyxfer/*` matches the `nostr+keyxfer://` scheme in §3.2 and
   is proposed throughout above; availability is unverified. `@sybenx/*` is the
   fallback and needs no check.
2. **Rust in the build**, for the FROST WASM path. Reasonable to defer to v0.4,
   but it shapes the `core` API now: FROST calls should sit behind an async
   interface from the first commit so the backend can change without a breaking
   release.
3. **License.** The repository carries one already; packages should state it
   explicitly per-package, and it is worth confirming it is the license you want
   on code as well as on prose.
4. **Whether §11's server is in scope for you at all.** A specification can
   name a server and let others build it. A library that promises §11 and ships
   no server is stuck. Deciding now changes the v0.2 milestone.
