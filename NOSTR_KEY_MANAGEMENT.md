# Nostr Key Transfer & Storage — Specification

Version 10.0-draft
Applies to: any client that holds a user's nsec (web, desktop, mobile)

> Transfer is specified in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) (QRST).
> **10.0 stops specifying a threshold-signing protocol of its own and adopts
> FROSTR** — [bifrost](https://github.com/FROSTR-ORG/bifrost)'s wire protocol and
> bech32m credential formats, and the `igloo` family of clients built on it — in
> place of everything §7 used to define (index architecture, epoch records,
> co-signer, device quorum, admission, rotation, revocation, recovery). §7 now
> holds only what FROSTR does not specify and what its own security checklist
> admits it does not have: a rotation construction (§7.9) and a recovery-delay
> proposal (§7.10), both offered back to FROSTR rather than specified for this
> document's own clients. §3.3 redefines `frost-share` as a FROSTR credential
> pair — a `bfshare1…` and its `bfgroup1…` — carried by QRST instead of the
> plaintext QR scan FROSTR's own apps use today. The passkey-default backup of
> §4.2 is unaffected; it never depended on §7's threshold design.

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

The base experience is: **the nsec lives on the user's devices, and gets to a new
device by the transfer mechanism of QRST.** That works on any device with a
network connection and nothing else.

Everything in this document — at-rest encryption, platform sync, backup,
threshold signing — is an addition on top of that base. An addition MUST degrade
to the base when its prerequisites are absent, with one declared exception:
threshold signing (§7) is FROSTR, adopted whole, and a FROSTR group by
construction needs a reachable threshold of its own peers to sign anything.
That trade is FROSTR's to state on its own onboarding screen, not this
document's.

## 1. Overview

An identity is an nsec. This document defines how a client stores it, how it is
backed up, and how it may optionally be split so that no single party holds a
usable copy.

How it reaches a new device is specified in QRST; §3 registers the two payload
profiles this document uses. The nsec is never displayed except when the user
explicitly exports or views it (§2.2, §4.1, privileged).

Where the platform already syncs secrets between the user's own devices, the
client uses that first and skips the handshake.

---

## 2. Storage

### 2.1 At rest

The client stores the nsec using the strongest mechanism the device supports,
probing top to bottom. Every level is acceptable; the lowest is the base.

| Level | Platform | Mechanism |
|---|---|---|
| 3 | iOS / macOS | Keychain item under `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with **no** biometric ACL (reads are silent while unlocked); privileged actions call `LAContext.evaluatePolicy` separately |
| 3 | Android | Keystore AES key **without** `setUserAuthenticationRequired` (silent while unlocked, StrongBox where available); privileged actions use `BiometricPrompt` separately |
| 2 | Windows / Linux desktop | Credential Locker / Secret Service, bound to the OS user account, silent read; privileged actions use `UserConsentVerifier` / a keyring prompt. Not hardware-bound. Probed first on Windows; DPAPI file is the fallback if Locker is unavailable. |
| 2 | Windows | DPAPI-protected file (never prompts; privileged actions proceed with an in-app confirm only) |
| 2 | Browser | nsec wrapped by a non-extractable WebCrypto AES-GCM key in IndexedDB (silent use); a user-verifying WebAuthn assertion additionally gates privileged actions (§2.3). Never level 3: the browser has no authenticator-bound decryption. |
| 1 | Any | App-private storage, unencrypted |

Probing MUST be silent and MUST NOT add onboarding steps. If a level-3 mechanism
requires user enrollment, the client stores at the next available level and MAY
show a one-time, dismissible notice offering to upgrade later. The client MUST
re-probe on launch and upgrade in place when a higher level becomes available.

On desktop browsers, if a NIP-07 extension is present, the client SHOULD offer to
hand the key to the extension. The offer is dismissible.

### 2.2 Unlock policy

The unlock threshold is a per-identity setting, `lock`, chosen by the user and
carried to new devices on the payload message (§3.1):

| `lock` | Behaviour |
|---|---|
| `device` (default) | The device's own login is the unlock. The client never prompts for ordinary signing. |
| `launch` | One prompt when the app starts; none until it exits. |
| `idle:<seconds>` | Prompt after that many seconds without interaction. |

In browsers, `launch` and `idle` prompts are consent steps, not cryptographic
locks — `W` decrypts silently for any code on the origin (§2.3).

Ordinary signing never prompts under `device`. On every platform, "device" means
the device: one unlock covers every tab, window, and process of the client.
Where FROSTR (§7) is in use, the device's `bfshare` and its peer keypair are
stored the same way, since a peer must answer signing and ECDH rounds silently.

**Privileged actions always prompt**, under every `lock` value, using the platform
authenticator. Levels 1–2 substitute the OS credential prompt where one exists and
otherwise proceed.

*Rule:* an action is privileged if and only if it touches the key itself — who
holds it, where a copy goes, or what protects it. Actions about content are never
privileged.

Privileged:
- Sending the key or a share to another device: acting as Sender (QRST §7 step 13, QRST §8 step 13).
- Showing or exporting the key: export (§4.1, always `ncryptsec`), viewing the nsec on screen (permitted, privileged, never written to disk).
- Splitting or rotating it: running FROSTR's dealer to activate threshold signing, rotation (§7.9).
- Cutting a device off: removing a peer from a FROSTR group's peer policy (§7.1), removing a device.
- Changing `lock`, or changing the backup password or passkey.

Never privileged: posting, replying, reacting, reading or sending DMs,
decrypting, receiving a key as Receiver, and any signature a website requests.

The prompt MUST state what it guards in one line ("Confirm — this sends your key
to *Laptop*"). A prompt the user cannot attribute to an action they just took is a
defect.

### 2.3 Browser and passkey procedure

```
Storage:
  W  = crypto.subtle.generateKey(AES-GCM-256, extractable = false, [encrypt, decrypt]); persist W in IndexedDB
  call navigator.storage.persist() at first use; IndexedDB is evictable without it
  ct = AES-256-GCM(W, nsec)                        // usable by any tab on this origin without a prompt

Passkey registration (all platforms, not only browsers):
  navigator.credentials.create({
    authenticatorSelection: {
      authenticatorAttachment: "platform",         // REQUIRED — see below
      residentKey: "required",
      userVerification: "required"
    },
    extensions: { prf: { eval: { first: SALT_A, second: SALT_B } } }
  })
  store credentialId, SALT_A, SALT_B (random 32 B each)

  SALT_A → privileged-action gate (§2.2)
  SALT_B → backup key derivation (§4.2)

Obtaining a PRF value:
  PRF-on-create is recent (Firefox 148+, Chrome 147+). Where the create call does not
  return prf.results, the client MUST immediately perform a get() with the same eval
  salts to obtain them. Both shapes MUST be handled.

Privileged-action gate:
  navigator.credentials.get({ ..., extensions: { prf: { eval: { first: SALT_A } } } })
  a verified assertion is the consent; the nsec is then read from `W` as usual.
```

**`authenticatorAttachment: "platform"` is required, not cosmetic.** Without it the
credential may land on a roaming security key or a device-bound authenticator,
both of which are useless for §4.2 recovery — recovery is the case where the
device is gone. On desktop Chrome, only passkeys saved to Google Password Manager
return a PRF value at all.

**Fail closed on status.** The client MUST NOT record a passkey backup as
established until a PRF value has actually been returned by a real assertion and
the resulting wrap has been accepted by the server. Reporting a backup that does
not exist is worse than reporting none, because the error surfaces only when
recovery is already the last option.

The PRF gate is a **consent step, not a cryptographic boundary** for storage: `W`
decrypts the nsec silently, so a hostile script on the origin is not stopped by
the passkey. Its use in §4.2 is different and is a real boundary there, because
the PRF value is origin-bound by the platform and cannot be produced by another
origin's dialog.

`W` is origin-scoped by the browser. Under `lock = device` there is no expiry.

### 2.4 Platform sync

The client MUST enable platform sync of the encrypted nsec where the platform
provides it and the user has that feature on:

| Platform | Mechanism |
|---|---|
| iOS / macOS | Second Keychain item with `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked` (iCloud Keychain) |
| Android | Block Store (`BlockstoreClient`) with cloud backup enabled. Keystore keys do not sync. |
| Browser | None; a browser is re-enrolled by transfer (QRST) |
| Desktop native | None |

On first launch the client MUST check for a synced copy before showing
onboarding. If present, and the client has no local record that this identity
ever activated FROSTR threshold signing, it restores silently and onboarding is
skipped.

**If the client's own local history shows it previously wiped this identity's
nsec to activate FROSTR (§7)**, a synced full-key copy is a stale pre-activation
backup: the device MUST **quarantine** the ciphertext — retained encrypted,
unusable, invisible to the UI — rather than restore it, and MUST show the
Receiver QR instead. This is a client-local check, not a protocol one: FROSTR
publishes no discoverable marker that an npub's signing authority has been
split, so a device with no memory of its own prior activation — a fresh
install syncing for the first time, for instance — has no way to detect one
and will restore the full key. Recording that history durably alongside the
platform-synced item (so a reinstall inherits it) is a client responsibility
this document does not further specify.

---

## 3. Transfer

Transfer is specified in QRST and is not restated here. This section defines the
two payload profiles and the transfer policy.

### 3.1 Profile `nostr-nsec`

Registered against QRST §5. Moves a whole identity key.

| QRST requirement | This profile |
|---|---|
| Payload encoding | 64 lowercase hex characters: the 32-byte private scalar. **Not bech32.** |
| Max size | Default (2048 B). A 32-byte payload is ~1.9 KB on the wire. |
| P4 check | 64 hex characters, decoding to a scalar in range for secp256k1 and yielding a valid x-only public key. |
| P5 rendering | Derive the npub, resolve a display name if cached, ask **"Log in as @name?"** |
| §5 prompt wording | "Send your key to *X*." The prompt MUST state that this is the identity itself and cannot be undone: there is no rotation in Nostr, and a party that receives this key keeps a working copy permanently. |
| Additional tags | `lock` — below. |

**`lock` tag**, on the payload message: `["lock", "<device|launch|idle:N>"]`.

**Sender restrictions.** If the sending device also holds a share of a FROSTR
group for this identity (§7), sending the whole nsec elsewhere reintroduces
exactly the single point of failure that group exists to remove. Clients
SHOULD warn before permitting it, but this document keeps no record of a
device's FROSTR participation to check automatically — that bookkeeping is
FROSTR's own.

This profile does **not** permit QRST's offline tier (QRST §10). To move a whole key
with no network — between two co-present screens — export it as NIP-49 `ncryptsec`
(§4.1) and import it on the other device; that standalone form is exactly why the
offline tier is unnecessary here (and why `frost-share`, which has no such form,
does permit it — §3.3).

### 3.2 Transfer policy

- Any device holding the nsec MAY act as Sender, subject to §3.1.
- A device that received its key by transfer defaults to **receive-only**. The
  toggle is one tap, unguarded, shown inline. Per QRST §14 it expires.
- Every transfer writes a local record
  `transfer_event { ts, profile, transport, sas, peer_burner, multi }`.
- There is no remote revocation in base mode. A "devices" list, if shown, MUST
  label removal as deleting the local copy only.

### 3.3 Profile `frost-share`

Registered against QRST §5. Threshold signing is not specified by this
document — it is [FROSTR](https://github.com/FROSTR-ORG/bifrost) (bifrost's wire
protocol and bech32m credential formats, and the `igloo` family of clients built
on it), adopted whole (§7). This profile exists because FROSTR names an
out-of-band channel for share distribution and does not specify one: its own
[security model](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/SECURITY.md)
lists "secure, authenticated channels (out-of-band)" as a trust assumption, and
its shipping clients meet that assumption by scanning a `bfgroup` QR and then a
`bfshare` QR **in plaintext** — the identical attack this document's transfer
mechanism exists to prevent (QRST's new §16 names the specific client). This
profile is that channel: it carries a FROSTR credential pair, unchanged, inside
QRST's SAS-gated, gift-wrapped envelope instead of a bare QR.

A joining peer needs two artifacts before it can speak to its group at all: its
own **share** and the **group** package that share belongs to (bifrost's own
`/onboard/res` returns the group package alone — [PROTOCOL.md](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/PROTOCOL.md#onboarding-protocol)
— because it assumes the share already reached the peer some other way). This
profile carries both, since a brand-new device has neither.

| QRST requirement | This profile |
|---|---|
| Payload encoding | Two bech32m strings, ASCII, joined by a single space: the peer's own `bfshare1…` (bifrost's `SharePackage` — a 4-byte member index and the 32-byte share scalar, 36 bytes) and the group's `bfgroup1…` (bifrost's `GroupPackage` — a 33-byte compressed group public key, a 4-byte threshold, and one `{index, pubkey}` per member, where `pubkey` is that member's own point `share_i·G`, not a polynomial coefficient commitment). Both wire formats are bifrost's own (`bifrost/src/encoder/{share,group}.ts`); this profile defines no encoding of its own, only the pairing. |
| Max size | Default (2048 B). Measured with `payload_ceiling.py`'s chain against bifrost's real wire sizes: a share is fixed at 72 characters; an `n`-member group runs 133 characters at `n = 1` to 1968 at `n = 32`. **32 members is the largest group this profile carries within the default budget** — one more pushes the pair to 2100 payload bytes, past the ceiling. At `n = 32` the wrapped event is 5997 bytes and the relay `EVENT` message 6007, comfortably inside every §11.6 tier (content ≤ 8196, event ≤ 65536, message ≤ 131072); no larger maximum is declared. `vectors/frost-share-max.json` is the P1 conformance vector, built from a real (seeded, reproducible) secp256k1 keyset at exactly this boundary and one member past it. |
| P4 check | Both strings decode without error against bifrost's encoder, which itself rejects a malformed size (36 bytes for a share; `37 + 37·n` for an `n`-member group). The share's `index` MUST appear in the group's `members` list, and `share·G` MUST equal that member's stored `pubkey`. This is bifrost's own share-verification shape — each member's point is carried directly in the group package, so there is no separate Feldman commitment step to check. |
| P5 rendering | Derive the group's npub by dropping the group public key's leading parity byte (bifrost stores it 33-byte compressed; a Nostr identity is the 32-byte x-only remainder) and resolve a display name if cached. Show **"share *N* of *M*, *K* required"** from the share's index, the member count, and the group's threshold, and state plainly that this device holds one share and cannot sign alone. |
| §5 prompt wording | "Give *X* a share of your key." Materially less severe than `nostr-nsec`: a lone share signs nothing, and a FROSTR group's own peer policy can simply stop answering that peer's requests. |
| Additional tags | None. A FROSTR peer's identity is the member pubkey already present in the transferred `bfgroup1…`; there is no separate enrollment keypair or device-list event (§7.1). |
| Offline tier (QRST §10) | Permitted, as the passphrase-encrypted container below. A raw, unencrypted credential pair MUST NOT be shown or pasted — the exact thing this profile exists to prevent. |

**Offline container.** Where no transport is reachable (QRST §10), the pair is
delivered as a passphrase-encrypted blob, unchanged from prior versions of this
document except in what it seals:

- **KDF:** scrypt with `r = 8, p = 1, log_n = 18` (matching §4.1), over the
  passphrase and a random 16-byte salt.
- **Cipher:** XChaCha20-Poly1305 with a random 24-byte nonce; the version byte is
  the associated data.
- **Plaintext:** the QRST payload above — the `bfshare1…` and `bfgroup1…`
  strings, space-joined. Sealing the pair, not only the share, also hides which
  identity it belongs to.
- **Container:** `version (0x01) || log_n (1) || salt (16) || nonce (24) ||
  ciphertext || MAC (16)`, then bech32 with HRP `frostshare` (per NIP-19, no length
  limit). Deliberately not a `bfshare1…` or `ncryptsec1…` string; the
  `frostshare1…` prefix and its checksum mark it as an encrypted pair and catch
  paste errors.

The receiver decrypts, applies the P4 check above, renders P5, and confirms (QRST
§10 step 3). Offline delivery has no admission-independent gate beyond the
passphrase, so it inherits the same reconstruction caveat as the §12.3 light
flow: an intercepted blob whose passphrase is guessed, plus one other member's
share, reconstructs the group secret.

---

## 4. Backup

### 4.1 When backup is offered

At the end of onboarding the client presents backup as the next step, with:

- Platform sync (§2.4), auto-detected and shown as already done if active,
- Blob-store backup (§4.2) — the default offer where a passkey is available,
- `ncryptsec` export (file or printable QR, `log_n = 18`).

The step is skippable ("Later"). If skipped, the client MUST NOT nag: no banner,
no scheduled reminders. Backup status is a passive line in settings.

**The client MUST offer backup again immediately before handing the nsec to
FROSTR's dealer to activate threshold signing (§7), before the local copy is
wiped.** This is not a nag: the user has just chosen to split their key, is
reading a screen about it, and is one step from having no full copy on any
device. It is the last moment at which the nsec exists locally and the user is
paying attention to it.

The export is always `ncryptsec`; the client MUST NOT export a raw nsec.

### 4.2 Blob store

A stateless HTTP service (reference: Cloudflare Worker + KV) that stores one
encrypted backup per identity. Used by §4.1 and reused by §7.10.

`CK` is wrapped independently under each enrolled recovery factor. **A passkey
factor is set up by default wherever a platform authenticator returns a PRF value;
a passphrase factor is always available and MUST NOT be omitted.** Either wrap
recovers the same `CK`.

```
Content, once per identity:
  CK          = random 32 B
  nsec_ct     = nonce || AES-256-GCM(CK, nonce, nsec)          // fixed for the identity's lifetime
  K_srv       = random 32 B, generated client-side, held by the server

Passphrase factor:
  salt_pw     = random 16 B
  K_pw        = scrypt(password, salt_pw, N = 2^18, r = 8, p = 1, dkLen = 64)
  K_auth_pw   = HKDF-SHA256(K_pw[32..64], salt = "auth-v1",      info = server base url)
  K_wrap_pw   = HKDF-SHA256(ikm = K_pw[0..32] XOR K_srv, salt = "blob-wrap-v1", info = npub_hex)
  ck_wrap_pw  = nonce || AES-256-GCM(K_wrap_pw, nonce, CK)

Passkey factor (default where available):
  prf         = PRF(credential, SALT_B)                          // 32 B, origin-bound by the platform
  K_auth_prf  = HKDF-SHA256(prf, salt = "prf-auth-v1",  info = server base url)
  K_wrap_prf  = HKDF-SHA256(ikm = HKDF(prf, "prf-enc-v1", npub_hex) XOR K_srv,
                            salt = "blob-wrap-v1", info = npub_hex)
  ck_wrap_prf = nonce || AES-256-GCM(K_wrap_prf, nonce, CK)

  blob = { nsec_ct, ck_wrap_pw, ck_wrap_prf? }

// where an identity's signing authority is split under FROSTR (§7), the PUT
// auth signature below is produced jointly by a threshold of peers rather than
// by a single held nsec — indistinguishable to the server, since a FROST
// signature verifies as an ordinary Schnorr signature. No special case needed.

PUT  /v1/backup { npub, salt_pw, blob, k_srv, K_auth_pw, K_auth_prf? }
     auth: Schnorr sig over a server challenge by the user's key
     server computes verifier_pw = HMAC-SHA256(k_srv, K_auth_pw), and verifier_prf likewise,
     then discards both K_auth values

GET  /v1/salt?npub=…   → { salt_pw, log_n, factors: ["pw"] | ["pw","prf"] }
     for unknown npubs returns HMAC(server_secret, npub) truncated to 16 B, always log_n = 18,
     always factors ["pw","prf"] — a factor list that varied would signal non-existence

POST /v1/recover { npub, K_auth }  → { blob, k_srv }
     the server compares K_auth constant-time against verifier_prf, then verifier_pw;
     the client does not declare which factor it used
```

**Release policy depends on which verifier matched, and this is the point of
having two.**

- **`verifier_prf` matched** → release immediately. The PRF value is origin-bound
  by the platform, so no other origin can produce it; there is no phishing path to
  delay against.
- **`verifier_pw` matched** → the server **MUST** hold release for a configurable
  delay (default 24 h), notifying every address the client has for the user's
  other devices by `RECOVERY_NOTICE` (kind 24316): "A recovery of your key
  started; it completes at …; approve or cancel from another device." A
  reachable device can approve instantly or cancel. With no address to notify,
  the delay elapses on its own. This document no longer maintains a device
  registry of its own (§7.1) to draw that address list from; a client MUST
  track enough of one — even informally — to make this notice reach somewhere,
  or the delay degrades to a timer nobody sees.

The password branch is the phishable one, so the friction sits there and
nowhere else. In 8.0 the delay was a blanket SHOULD; it is now a MUST on the
branch that needs it.

**Server storage.** Keys by `SHA-256(npub)`; stores `salt_pw`, `blob`, and the
verifiers in the data store, and `k_srv` in a separate secret store, never in the
same table as `blob`. `/recover`: constant-time compare; 10 attempts per hour and
30 per day per npub, 20 per hour per IP, exponential backoff; unknown npubs get the
same response time and shape as a wrong secret; no request logging beyond
rate-limit counters.

Properties:

- A leak of the data store alone is unbreakable: the verifiers are keyed by
  `k_srv`, so they cannot test guesses offline, and `blob` needs `k_srv` regardless.
- A leak of both stores reduces to the strength of the weakest enrolled factor. For
  a passkey factor that is 32 bytes of platform-held entropy; for a passphrase it is
  password strength at scrypt cost.
- The password is never sent; only `K_auth` is, over TLS to the enrolled URL.
- **A phished passphrase no longer yields the key on its own where a passkey factor
  is enrolled** — but it does yield it after the delay if the user approves the
  notice. The delay makes theft visible and cancellable; it does not make it
  impossible.

**Password screen.** Where a passphrase factor is being set up, the client MUST
pre-fill a generated six-word phrase (~96 bits) and the screen MUST carry: **"If
this server is ever hacked, this is the only thing protecting your key,"** and
**"Anyone who knows your npub and this server can try a few dozen guesses a day."**
In threshold mode the generated phrase MUST NOT be replaceable with free text: a
phrase the user has only ever seen inside this client is one a phishing dialog
cannot ask for convincingly, and a user-chosen password is one they will type
elsewhere and learn to type on request.

---

## 5. Security properties

Transfer properties are in QRST §15. The one that matters most here: a hostile
party acting as Receiver is not stopped by the code comparison, only by a user
declining the release prompt.

Base:

- The blob store never sees plaintext key material.
- Storage theft yields ciphertext bound to the device's secure hardware (level 3),
  to the OS user account or browser profile (level 2), or plaintext (level 1).
- A compromised unlocked device yields the key. Without §7, Nostr has no rotation.

Threshold signing (§7):

FROSTR's own [security model](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/SECURITY.md)
states what it protects against and what it does not — an M-of-N compromise
tolerance, and no share-in-transit protection assumed: its own trust
assumptions name "secure, authenticated channels (out-of-band)" for share
distribution rather than building one. Those properties, and their residual
risks, are FROSTR's to state and this document does not restate or
second-guess them. What this document still owns:

- **§3.3 is the channel FROSTR names but does not build.** A `bfshare`/`bfgroup`
  pair delivered by QRST is SAS-gated and gift-wrapped instead of the plaintext
  QR scan FROSTR's own clients use today.
- **Rotation (§7.9)** proposes a way to neutralise a departed or compromised
  member's retained share without reconstructing the group secret — a
  primitive FROSTR does not yet have (its own security checklist names the
  gap). Until FROSTR adopts it or an equivalent, the only rotation available
  anywhere is reconstruct-and-redeal, a real full-key exposure to get a clean
  result.
- **Recovery delay (§7.10)** proposes what a FROSTR group is owed when this
  document's own §4.2 recovery reconstructs the nsec elsewhere — a case
  FROSTR's peer-to-peer wire protocol has no message for at all, since every
  one of its channels is per-peer and this is a whole-group event.

---

## 6. Out of scope for v1

NIP-46 remote signing, own-npub monitoring, identity migration tooling.

**On rotation of the identity itself.** There is none in protocol: the nsec cannot
be changed and old copies cannot be invalidated. There is a social one — announce a
new key from the old one while you still control it — which costs the follower
graph, the history's attribution and every existing reference. Threshold mode
reduces attack surface going forward; it repairs nothing backwards.

---

## 7. Threshold signing

**Threshold signing is not specified by this document.** It is
[FROSTR](https://github.com/FROSTR-ORG/bifrost) — bifrost's wire protocol (Nostr
relay transport, ChaCha20-Poly1305-encrypted `/sign`, `/ecdh`, `/ping`, `/echo`
and `/onboard` messages) and its bech32m credential formats (`bfgroup1…`,
`bfshare1…`), together with the `igloo` family of clients built on it — adopted
whole. Everything this document used to specify itself — index architecture,
epoch records, activation, a co-signer mode, a device-quorum mode, admission,
signing, threshold ECDH, revocation, hostile-device and server-compromise
analysis, a lock indicator, its own rumor kinds — is FROSTR's now and is not
restated here. A client that wants threshold signing runs bifrost (or an
`igloo` client, or the Rust rewrite, `bifrost-rs`); §3.3 is this document's only
remaining involvement in getting a share there, and carries a FROSTR credential
pair over QRST instead of the bare QR FROSTR's own clients use today.

What remains below is two proposals **to FROSTR**, not specifications of
behaviour it already has, plus a short migration note:

- **§7.1** — how the enrollment-keypair-and-device-list model this document
  used to define maps onto FROSTR's own peer identities, for a client migrating
  off it.
- **§7.9 Rotation** — the half of rotation FROSTR is missing. `bifrost-rs` can
  already import a replacement share set; nothing in the ecosystem produces one
  without reconstructing the whole key first.
- **§7.10 Recovery delay** — an obligation FROSTR's wire protocol has no
  channel to carry, because reconstructing an nsec is a whole-group event and
  every FROSTR message is per-peer.

### 7.1 Peer identity (migration note)

Prior versions of this document specified a per-device **enrollment keypair**
`E`, a device list (kind 30242, `d = "devices"`), and an admission step gating
which `E.pub` a co-signer would answer. FROSTR needs none of it. A group's
members are the `{index, pubkey}` entries already carried in its `bfgroup1…`
(§3.3), where `pubkey` is the member's own point `share_i·G` in 33-byte
compressed form, and the peer's Nostr address is the x-only form of that same
point (`get_pubkey(share.seckey, 'bip340')`, `src/class/signer.ts`). Whether a
group answers a given peer's `/sign`, `/ecdh` or `/ping` requests is a
client-local **peer policy** — bifrost's `PeerConfig`/`PeerPolicy`, exposed by
`igloo-core`'s `policy.ts` — an allow-list a trusted device edits directly, not
a Nostr event this document defines.

A client migrating off the old design maps: `E.pub` → the x-only form of the
peer's member pubkey; admission → adding that pubkey to peer policy; revocation
short of rotation → removing it.

**Two things do not survive that mapping, and a migrating client should know
which.** The old `E` was deliberately *separate* from the share, and that
separation is what made revocation two-tier: revoking `E` took effect at once
and without touching a share. In FROSTR the two are one object — the share
secret is also the peer's identity and its transport key (§7.9) — so there is
no credential to revoke on its own, and no way to change a peer's identity
without rotating its share. Nor is the first tier enforced at a chokepoint any
more: with no server whose refusal is authoritative, peer policy is each peer's
own decision, so it is only as effective as the least-updated peer.

What does survive is the property that mattered: peer policy gates a group
*answering* a peer, not what that peer already holds. **It does not undo a
reconstruction.** An intercepted share plus `t − 1` others is the group secret
regardless of policy, which is exactly why §3.3 exists — to keep the share off
a channel where it can be intercepted at all.

### 7.9 Rotation (proposal to FROSTR)

**What FROSTR has today.** Nothing in `bifrost/src` computes a new share set
from an old one: grepping it for "rotat" returns nothing, and its docs return a
single hit — an open checklist item in
[`docs/SECURITY.md`](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/SECURITY.md#key-management),
"Rotate shares periodically if the protocol supports it." The Rust rewrite has
built the *host* half already: `bifrost-rs`'s
`finalize_rotation_update_import` (`crates/bifrost-profile/src/flows/rotation.rs`)
swaps a profile onto a replacement share set and journals the swap so a crash
mid-rotation is detectable afterwards. It takes that replacement as an
argument, and enforces exactly two invariants on it — the replacement group
package's `group_pk` MUST equal the current one's, and the replacement share
secret MUST differ (the profile id is derived from it). Those are precisely the
two properties the construction below provides. What is missing is upstream of
that call: the part that *produces* a replacement.

The only thing that produces one today is reconstruction. igloo desktop's
**Recover** screen calls `recoverSecretKeyFromCredentials` to rebuild the whole
nsec from `t` shares (`igloo-desktop/src/components/Recover.tsx`), and **Create**
re-deals a fresh keyset from it (`generateKeysetWithSecret`,
`src/components/Create.tsx`). For the case that pair was built for — shares lost
down to the threshold — it is the only thing that can work. For the ordinary
case, one member leaving or one device compromised, it puts the entire nsec back
on one screen in order to retire one share.

**The construction.** Re-randomising a sharing requires no secret material and
no threshold. A delta polynomial with a zero constant term leaves `a_0` — and
therefore `group_pk`, and therefore the npub — untouched, while moving every
member's share onto a new polynomial:

```
δ(x) = Σ_{j=1}^{t-1} r_j·x^j          δ(0) = 0, so the group secret never moves

Each contributor k (see "who contributes" below):
  δ_k(x)            = Σ_{j=1}^{t-1} r_{k,j}·x^j    fresh random r_{k,j}, one per coefficient
  commitments_k[j]  = r_{k,j}·G                    for j = 1..t-1
  publishes commitments_k[*] to every member
  sends δ_k(i) to member i, and to member i alone

Each member i, for each contributor k:
  verify δ_k(i)·G == Σ_{j=1}^{t-1} commitments_k[j]·i^j     // names a faulty contributor
then:
  δ(i)                = Σ_k δ_k(i)
  commitments[j]      = Σ_k commitments_k[j]                // public; anyone can sum it
  new_share_i         = old_share_i + δ(i)
  new_member_pubkey_i = old_member_pubkey_i + Σ_{j=1}^{t-1} commitments[j]·i^j
  new_group_pk        = old_group_pk
```

Nobody needs a share to compute a delta: `δ_k(i)` depends only on `i` and the
contributor's own coefficients, never on `f`. A rotation can therefore be run by
a single online device, which is the practical difference from
reconstruct-and-re-deal — that needs `t` members present *and* assembles the
nsec; this needs neither.

This carries the `t = 3` fix from SPEC_ISSUES.md, applied from the start rather
than patched in later. `commitments` is an **array**, one entry per non-constant
coefficient, so verification generalises to any `t` instead of hard-coding a
single `·i` term; every `r_{k,j}` is drawn fresh, one per contributor per
coefficient; and because the commitments cover only `j ≥ 1`, a member's check
also proves `δ(0) = 0` — a delta that moved the group secret cannot satisfy it.

**Who contributes, and why more than one.** One contributor is sufficient for
correctness and already achieves the immediate goal: a share retired before the
rotation no longer pairs with anything after it. More than one contributor buys
a different property. If a single party knows `δ` in full, then any share from
before the rotation can be converted into the matching share from after it, so
an attacker collecting shares across epochs is back to needing `t` *ever*
instead of `t` *within one epoch* — which is the whole point of rotating.
Contributions compose: an attacker must learn every contributor's `δ_k` to
link the two epochs, so every member that will remain SHOULD contribute, and a
client MUST NOT present a single-contributor rotation as providing cross-epoch
protection.

For the same reason, `δ_k(i)` MUST be sent confidentially and to one member
only. It is not share material and reads as harmless, but any `t − 1` of the
increments, plus the `δ(0) = 0` that everybody knows, interpolate `δ` entirely.
Bifrost's per-peer channel (ECDH to the recipient, ChaCha20-Poly1305) already
satisfies this; a broadcast of the same values would not.

**What rotating a share does to a live bifrost node.** This is the part a
proposal has to get right, because in bifrost a share secret is not only a share:

- **It is the member's identity in the group package.** `recover_secret_key`
  checks `get_pubkey(share.seckey, 'ecdsa')` against `group.members[].pubkey`
  (`src/lib/util.ts`), so the member entry is exactly `new_member_pubkey_i`
  above. The member list is rewritten by a rotation; indices are not, and need
  not be — `idx` is a 4-byte number with no contiguity requirement, and Lagrange
  interpolation is indifferent to which distinct values are used.
- **It is the peer's Nostr address.** A signer's pubkey is
  `get_pubkey(share.seckey, 'bip340')` (`src/class/signer.ts`), the x-only form
  of that same point. Rotating a share therefore moves every peer to a new
  address: subscriptions, `p` tags and every peer-policy entry keyed by pubkey
  (§7.1) move with it.
- **It is the transport key.** Message encryption derives from
  `get_shared_secret(share.seckey, peer_pubkey)`, so every pairwise channel
  rekeys at the same moment.
- **It changes the group id.** `gid = SHA256(group_pk ‖ threshold ‖ member
  pubkeys sorted by idx)` (`src/lib/group.ts`). `group_pk` is unchanged by
  construction, but the member pubkeys are not, so the `gid` — and every `sid`
  derived from it — changes. A peer still holding its pre-rotation share
  computes a different `gid` and is refused as `invalid_gid`; it does not
  degrade, it disappears.
- **It invalidates every outstanding nonce.** Secret nonces are HMAC-derived
  from the share secret (`derive_secret_nonce(share_secret, code)`,
  `src/lib/nonce.ts`), so a code a member issued before the rotation re-derives
  to different points afterwards and fails `verify_nonce`. Both pools MUST be
  dropped on rotation and replenished by `/ping`; signing MUST NOT be attempted
  against a pre-rotation nonce.

None of this needs a new message type — the increments and commitments fit the
existing encrypted peer channel — but all of it needs to happen together.

**Procedure.** Because the `gid` changes, a half-applied rotation does not
leave a degraded group; it leaves two groups that cannot address each other.
The ordering is therefore load-bearing:

1. Contributors draw their `δ_k`, publish `commitments_k[1..t-1]`, and send each
   member its own `δ_k(i)`. A member being retired is simply not sent one.
2. Each member verifies every contributor's increment against that
   contributor's commitments, sums the verified increments, and computes
   `new_share_i` and `new_member_pubkey_i`. A member that cannot verify
   **MUST** abort and keep its old share; the rotation has failed, and it
   failed for a named contributor.
3. Only once every remaining member has confirmed its new share does the group
   adopt the new `bfgroup1…`. A member MUST NOT delete its old share before it
   has stored and verified the new one, and a client SHOULD keep the old share
   until adoption is confirmed, since until then the old `gid` is the live one.
4. On adoption: each member re-encodes its own `bfshare1…` at its unchanged
   index, drops both nonce pools, re-subscribes at its new pubkey, and rewrites
   peer-policy entries to the other members' new pubkeys.
5. A member that misses the round is stranded in a specific way worth stating,
   because the obvious repair does not work. It is still listening at its old
   address, so a contributor that kept `δ_k(i)` can in principle deliver it
   there — but every other member's pubkey has changed too, so the stranded
   member sees only unrecognised senders and its own peer policy refuses them
   as `unauthorized`, while its own requests carry the pre-rotation `gid`.
   Either the rotation is held open until it returns, or it is re-onboarded
   rather than repaired: delivered a fresh `frost-share` pair (§3.3) by the
   surviving members, out of band, exactly as a new member would be.

**What rotation does not do.** It is forward-only. An attacker who already held
`t` shares from a single epoch has the group secret and rotating does not take
it back; what rotation removes is the ability to combine shares taken in
different epochs. And a contributor can hand its own `δ_k` to a retired member,
exactly as a member can hand over its share — rotation redistributes trust, it
does not manufacture any.

### 7.10 Recovery delay (proposal to FROSTR)

Recovery from all devices lost is unaffected by adopting FROSTR: it is still
§4.2, the passkey-or-passphrase blob-store recovery this document has always
specified, independent of whether the identity's signing authority happens to
be split across a FROSTR group at the time. §4.2's delay already exists for the
reason threshold mode makes sharper: the passphrase branch is phishable, and it
is the one an attacker can reach without stealing anything a device holds.

What FROSTR changes is what a completed recovery *means*. A recovered nsec is
the group secret, reconstructed in full, on a device that is not a member of
the group it came from. Every existing `bfshare` is now a share of a key that
also exists whole, somewhere else.

**Nothing in FROST repairs that, and this section must not imply otherwise.**
Rotation (§7.9) cannot: it preserves `a_0` by construction, which is exactly
what lets it keep the npub, so it moves shares around a secret that has already
left. Re-dealing cannot either — a fresh dealing from the same nsec is a second
sharing of the same secret, and the first one keeps working, because `t` of the
old shares still reconstruct the same key. §6 has already given the reason: the
identity *is* the key, and there is no rotation of it in protocol. A completed
recovery is therefore not something a group recovers from cryptographically.
It is something the members have to be **told**, while being told is still
worth something.

bifrost has nowhere to tell them. Its wire protocol carries `/sign`, `/ecdh`,
`/ping`, `/echo` and `/onboard`; none of them means "the secret you hold a
share of now also exists whole elsewhere." Every channel it has is per-peer and
request-shaped, and this is a single fact about the whole group. A member never
told keeps signing normally, with no way to learn that its share is no longer
the only route to the key.

This section proposes two things. First, the notice §4.2 already sends on a
password-branch recovery — `RECOVERY_NOTICE` (kind 24316) — MUST also reach
every pubkey in the group's `bfgroup1…` member list wherever the recovering
client can name one: a cached group package, a prior export, or the user naming
it directly. Second, a client completing such a recovery MUST hold the identity
**recovery-pending**, and MUST NOT present the recovered nsec as an ordinary
key, until the user has been shown that the old group's shares still work and
has chosen what happens to them — retire that group and deal a new one, or keep
it and destroy the recovered copy. Passkey-branch recovery releases without a
delay because there is no phishing path to delay against (§4.2); it carries the
same notice and the same pending state, without the delay.

The delay is what makes the notice worth sending rather than merely polite.
§4.2 already lets a device that receives one cancel the recovery outright, and
the delay is the only window in which that power exists: before it elapses a
member can stop a phished recovery, and after it elapses there is nothing left
to stop. Reaching the members inside that window is the difference between a
theft that can be cancelled and one that is merely disclosed afterwards.

This changes nothing about §4.2's own timing. It states what a FROSTR group is
owed once a recovery starts — a gap of FROSTR's own making, since a protocol
whose channels are all per-peer has nowhere to put a message about an event
that happens to the whole group at once — and one this document cannot close
alone: a recovering client only knows which `bfgroup1…` to notify if it, or the
user, kept one.

## Appendix A — References

NIP-07, NIP-44, NIP-49, NIP-59. RFC 9591 (FROST). BIP-340. WebAuthn Level 3 (PRF
extension). Transfer: [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md). Threshold
signing: [FROSTR / bifrost](https://github.com/FROSTR-ORG/bifrost),
[igloo-core](https://github.com/FROSTR-ORG/igloo-core),
[bifrost-rs](https://github.com/FROSTR-ORG/bifrost-rs).
