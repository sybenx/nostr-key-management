# Nostr Key Transfer & Storage — Specification

Version 8.0-rc1
Applies to: any client that holds a user's nsec (web, desktop, mobile)

> Transfer is specified in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md). What
> used to occupy §§3–6 and §8 of this document has moved there; §3 is what
> remains — a pointer, the two payload profiles, and transfer policy.
> Sections are contiguous. Anything citing the pre-split numbering — §§4–6 or §8
> for transfer, or §§5–11 for security, scope and the server — predates the
> split.

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

The base experience is: **the nsec lives on the user's devices, and gets to a new device by the transfer mechanism of [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md).** That works on any device with a network connection and nothing else.

Everything in this document — at-rest encryption, platform sync, backup, threshold signing — is an addition on top of that base. An addition MUST degrade to the base when its prerequisites are absent. Nothing here may prevent a user from logging in, transferring, or using their key on a device that lacks a feature.

## 1. Overview

An identity is an nsec. This document defines how a client stores it, how it is backed up, and how it may optionally be split so that no single party holds a usable copy.

How it reaches a new device is specified separately, in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md); §3 registers the two payload profiles this document uses with it. The nsec is never displayed except in that specification's offline fallback and when the user explicitly exports or views it (§2.2, privileged).

Where the platform already syncs secrets between the user's own devices, the client uses that first and skips the handshake.

---

## 2. Storage

### 2.1 At rest
The client stores the nsec using the strongest mechanism the device supports, probing top to bottom. Every level is acceptable; the lowest is the base.

| Level | Platform | Mechanism |
|---|---|---|
| 3 | iOS / macOS | Keychain item under `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with **no** biometric ACL (so reads are silent while the device is unlocked); privileged actions call `LAContext.evaluatePolicy` separately |
| 3 | Android | Keystore AES key **without** `setUserAuthenticationRequired` (silent while unlocked, StrongBox where available); privileged actions use `BiometricPrompt` separately |
| 2 | Windows / Linux desktop | Credential Locker / Secret Service, bound to the OS user account, silent read; privileged actions use `UserConsentVerifier` / a keyring prompt. Not hardware-bound; not level 3. Probed first on Windows; DPAPI file is the fallback if Locker is unavailable. |
| 2 | Windows | DPAPI-protected file (never prompts; privileged actions proceed with an in-app confirm only) |
| 2 | Browser | nsec wrapped by a non-extractable WebCrypto AES-GCM key in IndexedDB (silent use) — one storage path; when a platform authenticator exists, a user-verifying WebAuthn assertion additionally gates privileged actions as a consent step (§2.3). Never level 3: the browser has no authenticator-bound decryption. |
| 1 | Any | App-private storage, unencrypted |

Probing MUST be silent and MUST NOT add onboarding steps. If a level-3 mechanism requires user enrollment (e.g. no biometric set up, no passkey), the client stores at the next available level and MAY show a one-time, dismissible notice offering to upgrade later. The client MUST re-probe on launch and upgrade in place when a higher level becomes available.

On desktop browsers, if a NIP-07 extension is present, the client SHOULD offer to hand the key to the extension. The offer is dismissible.

### 2.2 Unlock policy
The unlock threshold is a per-identity setting, `lock`, chosen by the user and carried to new devices on the payload message (§3.1):

| `lock` | Behaviour |
|---|---|
| `device` (default) | The device's own login is the unlock. The client never prompts for ordinary signing. |
| `launch` | One prompt when the app starts; none until it exits. |
| `idle:<seconds>` | Prompt after that many seconds without interaction. |

In browsers, `launch` and `idle` prompts are consent steps, not cryptographic locks — `W` decrypts silently for any code on the origin (§2.3); the same is already true of the privileged-action gate.

Ordinary signing never prompts under `device`. On every platform, including the browser, "device" means the device: one unlock covers every tab, window, and process of the client on that device. Level-3 storage is therefore configured so reads never prompt; the authenticator is invoked only by the privileged-action gate below. The enrollment key `E` (§7.1) is stored the same way, since it must sign co-signing rounds silently.

**Privileged actions always prompt**, under every `lock` value, using the platform authenticator (biometric/OS credential; PRF assertion in the browser). Levels 1–2 substitute the OS credential prompt where one exists and otherwise proceed.

*Rule:* an action is privileged if and only if it touches the key itself — who holds it, where a copy goes, or what protects it. Actions about content are never privileged.

Privileged:
- Sending the key or a share to another device: acting as Sender (QRST §7 step 13, QRST §8 step 13, and §7.7 below).
- Showing or exporting the key: export (§4.1, always `ncryptsec`), viewing the nsec on screen (permitted, privileged, never written to disk), enrolling a server (§7.2 uploads a backup).
- Splitting or refreshing it: enabling threshold signing, refresh, Offline mode on or off (and allowing it for another device), keep-key on or off, disabling threshold signing.
- Cutting a device off: remove device, change role.
- Changing `lock`.

Never privileged: posting, replying, reacting, reading or sending DMs, decrypting, completing a signing round for another of the user's devices, receiving a key as Receiver, and any signature a website requests.

The prompt MUST state what it guards in one line ("Confirm — this sends your key to *Laptop*"). A prompt the user cannot attribute to an action they just took is a defect.

### 2.3 Browser procedure
```
Storage:
  W  = crypto.subtle.generateKey(AES-GCM-256, extractable = false, [encrypt, decrypt]); persist W in IndexedDB
  call navigator.storage.persist() at first use; IndexedDB is evictable without it
  ct = AES-256-GCM(W, nsec)                        // usable by any tab on this origin without a prompt

Privileged-action gate (level 2+ browsers):
  Registration: navigator.credentials.create({ ..., authenticatorSelection: { userVerification: "required" } })
                if no platform authenticator is available → plain level 2; privileged actions use an in-app confirm only
                store credentialId, SALT_A, SALT_B (random 32 B each)
  Gate:         navigator.credentials.get({ ..., extensions: { prf: { eval: { first: SALT_A, second: SALT_B } } } })
                a successful assertion (signature verified against the stored credential public key) is the consent;
                the nsec is then read from `W` as usual. `userVerification: "required"` is what makes the assertion
                a biometric/PIN event. PRF is not used in v1.
```
`SALT_B` is reserved and MUST NOT be used in v1.

The PRF gate is a **consent step, not a cryptographic boundary**: `W` decrypts the nsec silently, so a hostile script on the origin is not stopped by the passkey. The gate stops a person at an unlocked machine, which is its purpose; the origin itself is trusted by definition, and §7's restricted role exists because of exactly this.

`W` is origin-scoped by the browser: only this site's own code can use it. Other sites, other origins, and extensions without host permission for this origin cannot reach it. Under `lock = device` there is no expiry; a browser a user has logged into stays logged in until they remove the device or change `lock`.

### 2.4 Platform sync
The client MUST enable platform sync of the encrypted nsec where the platform provides it and the user has that platform feature turned on:

| Platform | Mechanism |
|---|---|
| iOS / macOS | Second Keychain item with `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked` (iCloud Keychain) |
| Android | Block Store (`BlockstoreClient`) with cloud backup enabled; the platform encrypts end-to-end under the lockscreen credential without the app seeing it. Keystore keys do not sync. |
| Browser | None; a browser is re-enrolled by transfer (QRST) |
| Desktop native | None |

On first launch the client MUST check for a synced copy before showing onboarding. If present, it restores silently and onboarding is skipped, and the device **self-enrolls**: it generates `E`, signs an updated device list adding its own `E.pub` (label = platform + model, role = trusted, since it restored from the user's own platform account), and publishes it. Before self-enrolling, the restored device fetches the epoch record (the plaintext `epoch` tag suffices). If the fetch fails (offline, relays unreachable), it MUST wait and retry — self-enrolling on stale information is the dangerous branch; the key stays dormant until the record's presence or absence is established. **Absence is only established** after querying a relay the user controls or pays for (when configured) or, otherwise, after a 24-hour retry window — a withholding relay can manufacture absence, and absence is what unlocks self-enrollment with a full key. If an **active threshold record exists**, a restored nsec is a stale full-device backup taken before activation: the device **quarantines** the ciphertext (retained encrypted, unusable, invisible to the UI), writes the threshold marker, and shows the Receiver QR; the quarantined copy is deleted only once a co-signer completes a round for this device or the record is re-confirmed after 7 days — so a relay serving a stale *active* record (or withholding a `disabled` one) cannot trick the device into destroying the only key. Only when no active record exists does it self-enroll with the key. A restored device that does self-enroll therefore always appears on the list and is wiped at activation like any other. If instead it finds the §7.5 threshold marker, it holds no key: it shows the Receiver QR (QRST) so an existing member can issue it a share.

---

## 3. Transfer

Transfer is specified in **[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md)**
(QRST) and is not restated here. Devices pair by QR or by copying the URI, the
sending device's user types a five-digit code shown on the receiving device, and
the payload travels gift-wrapped over public relays.

This section defines what QRST leaves to its consumers: the two payload profiles
this document uses, and the transfer policy that applies to both.

### 3.1 Profile `nostr-nsec`

Registered against QRST §5. Moves a whole identity key.

| QRST requirement | This profile |
|---|---|
| Payload encoding | 64 lowercase hex characters: the 32-byte private scalar. **Not bech32.** |
| P1 tier | Tier 1. A 32-byte payload is ~1.9 KB on the wire and clears every relay limit. |
| P4 check | 64 hex characters, decoding to a scalar in range for secp256k1 and yielding a valid x-only public key. |
| P5 rendering | Derive the npub, resolve a display name if one is cached, and ask **"Log in as @name?"** |
| §5 prompt wording | "Send your key to *X*." The prompt MUST state that this is the identity itself and cannot be undone: there is no rotation in Nostr, and a party that receives this key keeps a working copy permanently. |
| Offline fallback (§6) | Permitted, with restrictions below. |
| Additional tags | `lock`, `enroll` — below. |
| Companion messages | One: the user's relay list. |

**`lock` tag**, on the payload message: `["lock", "<device|launch|idle:N>"]`. It
carries the sending user's unlock threshold (§2.2) so the preference travels with
the key rather than resetting on each new device.

**`enroll` tag**, on the request and acknowledgement messages:
`["enroll", "<E.pub hex>", "<label proposal>"]`. `E` is the receiving device's
stable enrollment keypair (§7.1) — distinct from the QRST burner, which is
destroyed when the session ends. The sending device reads `E.pub` and adds it to
the device list; the label is a default its user may override.

Enrollment happens *during* the transfer deliberately. Every §7 operation —
share issuance, refresh deltas, offline requests, audit digests, removal — must
reach a device long after the session is over, and needs a stable address to do
it. The transfer is the one moment when a channel already authenticated by the
SAS and a user already paying attention are both available. Enrolling afterwards
would require a second ceremony with neither.

**Offline fallback.** The passphrase-encrypted encoding required by QRST P7 is
NIP-49 `ncryptsec` with `log_n = 18`, KSB `0x02`. The sending device MUST show
the line **"Anyone who photographs this code can try passwords against it
forever; this passphrase is the only protection."**

**Sender restrictions** (QRST §5 permits a profile to impose these). In threshold
mode the offline fallback is unavailable toward restricted targets and available
only from a keep-key device — the only device that legitimately holds a whole
nsec. An Offline-mode device's two shares are the polynomial and MUST NOT be
exported; handing an origin a whole nsec off-grid would bypass every §7
invariant at once.

### 3.2 Transfer policy

- Any device holding the nsec MAY act as Sender, at any storage level, subject to
  the restrictions in §3.1.
- A device that received its key by transfer defaults to **receive-only**. The
  toggle is one tap, unguarded, and the transfer screen shows it inline ("This
  device is receive-only — allow sending?") rather than hiding the option.
  Per QRST §14 it expires rather than persisting.
- Every transfer writes a local record
  `transfer_event { ts, profile, transport, sas, peer_burner, multi }` visible in
  settings. (QRST §14 requires this; the field formerly called `rung` is now
  `profile` plus `transport`.)
- There is no remote revocation in base mode. A "devices" list, if shown, MUST
  label removal as deleting the local copy only.

---

### 3.3 Profile `frost-share`

Registered against QRST §5. Issues one threshold share to a device joining an
already-activated identity (§7.7).

| QRST requirement | This profile |
|---|---|
| Payload encoding | A `KEY_SHARE_PART` value per §7.7. |
| P1 tier | Tier 1. |
| P4 check | `share·G == group_pub + commitment·index` for the receiving index. |
| P5 rendering | The identity the share belongs to, and that this device will hold **one share, not the key** — it will be unable to sign alone. |
| §5 prompt wording | "Give *X* a share of your key." This is materially less severe than `nostr-nsec` and the prompt SHOULD say so: a share alone signs nothing, and the device can be revoked later. |
| Offline fallback | **Not permitted.** |
| Additional tags | `enroll`, as above. |
| Companion messages | None. |

> **Open: this profile does not fit QRST's model cleanly.** §7.7 has the joining
> device receive *two* partials — one from a trusted device, one from the server —
> which it sums. QRST describes one Sender, one Receiver, one payload, and its
> attribution check (QRST §11.4) would reject a second partial arriving from a
> party that is not the Sender.
>
> The likely resolution is that the trusted device is the QRST Sender and the
> server's partial is delivered outside the QRST session, addressed to the same
> burner — but that needs specifying, and QRST's attribution rule needs an
> explicit carve-out or the burner needs to accept a named second writer. Do not
> implement `frost-share` until this is settled.
>
> This profile is deliberately the last subsection of §3. It exists only to serve
> threshold signing (§7), so if that is ever dropped or split out, both go and
> nothing renumbers.

## 4. Backup

### 4.1 Onboarding prompt
At the end of onboarding the client presents backup as the next step, with one of:
- Platform sync (§2.4), auto-detected and shown as already done if active,
- ncryptsec export (file or printable QR, `log_n = 18`),
- Blob-store backup (§4.2).

The step is skippable ("Later"). If skipped, the client MUST NOT nag: no banner, no scheduled reminders. Backup status is shown as a passive line in settings ("Backup: none / iCloud Keychain / server"). The client MAY show the offer once more, dismissibly, immediately after the user completes a transfer as Sender. The client MUST NOT block login, posting, or transfer on backup status.

The export is always `ncryptsec`; the client MUST NOT export a raw nsec.

### 4.2 Blob store
A stateless HTTP service (reference: Cloudflare Worker + KV) that stores one encrypted backup per identity. Used directly by §4.1 and reused unchanged by §7.2/§7.10.

```
Client (setup, on a trusted device):
  salt     = random 16 B
  K_pw     = scrypt(password, salt, N = 2^log_n, r = 8, p = 1, dkLen = 64)    log_n = 18, fixed for the blob store (a 17 option would make its bearer enumerable via §4.2 anti-enumeration); local-only §4.1 and QRST §10 exports MAY use 17 on low-memory devices. Recovery needs ~512 MiB free; the client says so if the device lacks it
  K_enc    = K_pw[0..32]                                     // never leaves the device
  K_auth   = HKDF-SHA256(K_pw[32..64], salt = "auth-v1", info = server base url)   // per-server: a removed server's credential is useless elsewhere
  K_srv    = random 32 B                                     // generated client-side, held by server
  K_wrap   = HKDF-SHA256(ikm = K_enc XOR K_srv, salt = "blob-wrap-v1", info = npub_hex)
  CK       = random 32 B                                     // content key, generated once per identity
  nsec_ct  = nonce || AES-256-GCM(CK, nonce, nsec)            // fixed for the identity's lifetime
  ck_wrap  = nonce || AES-256-GCM(K_wrap, nonce, CK)          // per server / per password
  blob     = { nsec_ct, ck_wrap }                            // nonces random 96 bits; the §4.1 file export is separately ncryptsec
  PUT  /v1/backup   { npub, salt, blob, k_srv, K_auth }   auth: Schnorr sig over a server challenge by the user's key
                    (base mode), or by a trusted E.pub on the current device list (threshold mode — the server holds the
                    group secret and can read the list; group-key digest signing is unavailable by design, §7.6)
                    server computes verifier = HMAC-SHA256(key = k_srv, K_auth) and discards K_auth

Client (recovery, on a trusted device, nothing else available):
  GET  /v1/salt?npub=…                        → { salt, log_n }   for unknown npubs returns HMAC(server_secret, npub) truncated to 16 B as salt and always log_n = 18 (matching the overwhelming real-user value; a mixed fake distribution would itself signal non-existence)
  derive K_pw from password + salt
  POST /v1/recover { npub, K_auth }           → { blob, k_srv } only if HMAC-SHA256(k_srv, K_auth) == verifier
  K_wrap as above → decrypt

Server:
  keys by SHA-256(npub); stores salt, blob, verifier in the data store
  stores k_srv in a separate secret store (e.g. Worker secret binding / per-user KV in a second namespace), never in the same table as blob
  /recover: constant-time compare; 10 attempts per hour and 30 per day per npub, 20 per hour per IP, exponential backoff
            unknown npubs get the same response time and shape as a wrong password
            an attacker who knows the URL and npub can exhaust the per-npub quota and delay a user's recovery by hours; this DoS is accepted
            30 online guesses a day, with no password floor, is enough to find a top-few-hundred password in weeks without any breach; the password screen says so
  no request logging beyond rate-limit counters
```
Why the indirection: changing the password or adding a server only re-wraps `CK` under a new `K_wrap`. In threshold mode `CK` is distributed to trusted devices alongside their shares (§7.5), so those operations never reconstruct the nsec. A trusted device holding `CK` plus the server's `nsec_ct` is the key — which is already true of trusted device + server per §5, so nothing is lost.

Properties, honestly stated:
- A leak of the data store alone (salt, blob, verifier) is unbreakable: `verifier` is keyed by `k_srv`, so it cannot be used to test password guesses offline, and `blob` needs `k_srv` regardless. (A plain hash verifier would have let a data-store leak be cracked offline and then redeemed with a single correct online call.)
- A leak of both stores reduces to password strength at scrypt cost. No single-server construction avoids this; OPAQUE does not either, since the server's OPRF key would be in the same leak.
- An attacker with only a URL and npub gets rate-limited online guesses, never the ciphertext.
- The password is never sent; only `K_auth` is, over TLS to the enrolled URL.

**Recovery delay (SHOULD; default on whenever the server knows at least one `E.pub` to notify — backup-only users are equally phishable, so enrollment registers the enrolling device's `E.pub`, and later devices register on first contact; this leaks device count to the server, which threshold servers already see).** Notices are `RECOVERY_NOTICE` wraps (kind 24316) to each registered `E.pub`. On a correct `/recover`, the server holds release for a configurable delay (default 24 h), immediately notifying every enrolled member ("A recovery of your key started; it completes at …; approve or cancel from any trusted device"). A trusted device can approve instantly or cancel; with no devices left, the delay simply elapses. This converts a phished password from an instant key into a raced, visible one.

Because there is no password floor (§7.2), the password screen MUST show the two warning lines in §7.2 step 2.

---

## 5. Security properties

**Transfer properties are stated in QRST §15 and are not repeated here.** The one
that matters most to this document: a hostile party acting as Receiver is not
stopped by the code comparison — only by a user declining the release prompt —
and §7's restricted role is what bounds the damage once threshold mode is on.

Base:
- The blob store never sees plaintext key material.
- A hostile enrolled website can phish the backup password with a fake dialog; the recovery delay makes the resulting theft visible and cancellable, but a user who confirms a phished recovery loses the key. Residual risk.
- Storage theft yields ciphertext bound to the device's secure hardware (level 3), to the OS user account or browser profile (level 2), or plaintext (level 1, by the user's choice).
- Blob store: a dumped database is unbreakable without `K_enc`; a URL and npub buy rate-limited guesses; a fully compromised server reduces to password strength at scrypt cost.
- A compromised unlocked device yields the key. Without §7, Nostr has no rotation; this is out of scope.

Threshold mode (§7):
- **At `t = 2`, any two shareholders reconstruct the key.** Server and site, server and trusted device, or trusted device and site each suffice. Collusion is not a protocol event — shareholders may simply exchange share values — so no audit, rate limit, allowlist or approval in §7 constrains it. The guarantee of this mode is that no *single* party holds a usable key; it is not a guarantee against two parties agreeing. A user who enrolls no server (§7.6 makes trusted devices the normal co-signers in that case) has no second party to collude with, and that is the only in-design answer to this.
- Once every device has ACKed, no device, site, or server holds a usable key *alone*: each holds one share; replicas of the same index never combine; the backup holds the key under the password. Until every device has ACKed, the non-ACKed devices still hold the full key and are shown as such.
- A hostile site is limited per §7.13. A compromised server is limited per §7.12.
- Refresh (§7.9) invalidates every old share without reconstructing; only §7.15 disable reconstructs, on a trusted device, at the user's request.
- Keep-key (§7.5) and Offline mode (§7.14) are explicit exceptions the user creates with a second device's approval; they are shown in the lock state. Both are trusted-device-only, because a device that has held two shares cannot be un-trusted by refresh.
- Permanent `#p = E.pub` subscriptions let a relay count a user's devices and see per-device activity timing under a stable key. Not mitigated in v1.
- The server (or any trusted co-signer) sees the plaintext of every event a share-only device signs through it, and the peer pubkey of every NIP-04/44 conversation key it helps derive. It does not see DM contents.
- A compromised trusted device can start a refresh war; the resolution is recovery from backup on a clean device (§7.10).
- **A compromised trusted device plus a reachable server is the key.** It can enroll a Receiver it controls (§7.7) or run disable (§7.15), and share + share reconstructs. Threshold mode therefore protects against hostile sites, hostile or compromised servers, and lost *restricted* devices; it does not protect against a rooted trusted device, which is the same threat as a rooted phone in base mode. Users with two or more trusted devices MAY turn on **two-device approval** (§7.1), after which issuance, disable, keep-key, and reconstructing operations require a tap on a second trusted device and a single compromised trusted device is limited to co-signing.

---

## 6. Out of scope for v1
NIP-46 remote signing, own-npub monitoring, identity migration tooling. These do not change any decision above; a later version may add them.

**On rotation, since §5 says there is none.** There is no rotation *in protocol*:
the key cannot be changed and old copies cannot be invalidated. There is a social
one — announce a new key from the old one while you still control it, and ask
people to follow the new identity. It is expensive rather than impossible: the
follower graph, the history's attribution and every existing reference are lost,
and anyone who misses the announcement keeps trusting the old key. That is what
people actually do after a key is exposed, and it is the reason threshold mode
reduces attack surface going forward rather than repairing anything backwards.

## 7. Server: backup and optional threshold signing

Additive per §0. Nothing in this section alters §1–10. A user who never enrolls a server is unaffected.

**Server independence.** Every operation in this section — signing, share issuance, refresh, Offline mode, disabling — MUST be completable with two of the user's own devices and no server reachable. A server is a replica of share 1 that happens to be always on; it is never a requirement.

### 7.1 Enrollment keys and device list
Every device generates a stable secp256k1 **enrollment keypair** `E` at install (stored per §2.1). The client maintains a **device list** — `{E.pub, label, role, storage_level, mode}` per device — in a parameterised replaceable event (kind 30242, `d = "devices"`), signed by the user's key. In base mode it is NIP-44-encrypted to the user's own pubkey. In threshold mode a share-only device cannot compute `nsec·P` without a round, so the content is instead encrypted (NIP-44 v2 payload format with a symmetric conversation key) under a **group secret**: a random 32-byte value distributed alongside every share in `KEY_SHARE` and `KEY_SHARE_PART` and replaced by a fresh one carried in every `KEY_REFRESH`. The epoch record (§7.4) is encrypted the same way. During every transfer the Sender reads the Receiver's `E.pub` from the `enroll` tag of `KEY_REQUEST` or `TRANSFER_ACK` and adds it to the list; the label proposal is a default the Sender's user may override. Each device subscribes to `#p = E.pub` permanently for §7 wraps, with `since` = a persisted last-seen cursor minus 2 days, and never less than 32 days back on first subscribe or after a gap — QRST §11.5's 2-day window is for burners only. This costs the user nothing and is required for §7.4 onward.

**Roles.** `trusted` — native app on a device the user owns; may sign, refresh, issue shares, act as helper, approve requests, remove devices. `restricted` — every browser-origin device; may sign ordinary content and send requests, nothing else: never Sender, never helper, never refresh initiator. **A Receiver's role is chosen by the Sender's user, never by the Receiver.** `plat`/`origin` are unverified, so they inform the prompt but never the role. The Sender's consent prompt (QRST §9) carries an unchecked box, **"Trust this device — it's my own app on hardware I own,"** defaulting to restricted for everything. Ticking it assigns trusted. When two-device approval (below) is on, ticking it additionally requires an `APPROVAL` from a second trusted device. Role can later be changed only from a trusted device. A phishing page that claims `plat=linux` therefore still lands on index 2 unless the user affirmatively ticks the box. Servers enforce role on every privileged endpoint; devices enforce it on every privileged wrap.

**Two-device approval (optional).** A setting on the devices screen, available when two or more trusted devices are enrolled, off by default. When on, every operation that issues a new index, releases share 1, or reconstructs (§7.7, §7.14 enter, §7.15, and the reconstructing operations in §7.5a) requires an `APPROVAL` (kind 24311) signed by a second trusted `E.pub` naming the operation, the requester, a unique request-id, and a 10-minute expiry — verifiers reject reuse and expiry, so an APPROVAL cannot be replayed within the 30-day wrap window; servers and helper devices MUST verify it before contributing. The prompt on the approving device names the operation and consequence in one line. The toggle itself says: "With exactly two trusted devices, losing one means recovering from backup." Without this setting, one trusted device plus a server suffices, and §5 states what that means.

**Labels** are written by the Sender at enrollment (defaulting to platform + model, or origin for browsers) and edited only from trusted devices. A Receiver MUST NOT be able to set or change its own label.

### 7.2 Server enrollment
A server is a Nostr-speaking service with a stable enrollment keypair `S` and an HTTPS base URL.

1. Server displays a QR: `qrst://<S.npub>?v=1&mode=server&url=<https base url>` (or a copied URI, QRST §12.1).
2. Phone scans. Client prompts: **"Backup password"** — pre-filled with a generated six-word PGP phrase (~96 bits) the user may keep or replace with anything; no minimum, no rules. The screen carries two lines: **"If this server is ever hacked, this password is the only thing protecting your key,"** and **"Anyone who knows your npub and this server can try a few dozen passwords a day."** Server enrollment, and any entry of the backup password, happens only on trusted devices; a restricted device MUST NOT present a backup-password field. A strength meter MAY be shown; it MUST NOT block.
3. Client runs §4.2 setup against `<url>` with the password entered in step 2. The server stores `salt`, `blob`, `k_srv`, `verifier`; nothing else about the key.
4. Client shows the **mode screen** (§7.3).

Enrolling a second server repeats steps 1–3; the blob is uploaded to every enrolled server. In threshold mode a trusted device re-wraps `CK` for the new server (§7.5a); no reconstruction.

### 7.3 Mode screen (mandatory, shown once per server enrollment)
Shown only if the device list contains **at least two devices, at least one of them trusted** (a native app). With fewer, threshold signing is not offered and the enrollment is backup-only. Two browsers alone do not qualify: both would hold index 2 and neither could refresh, help, or disable. With exactly one trusted device, losing it means recovery is via the backup (§7.10); the client says so on this screen.

Exactly two options. **B is preselected.**

> **A — Threshold signing**
> Your key is split into pieces so no device or website holds a usable copy; the only full copy is your encrypted backup. Any device can post and read DMs while your server or another of your devices is reachable, and any device can be revoked. Your server sees what your other devices post (not the contents of DMs). To use a device with nothing reachable, turn on **Offline mode** for it first — it needs a tap from one of your other devices.
>
> **B — Backup only (recommended)**
> Your key stays on all your devices as it is now. The server holds an encrypted backup you can restore with your password.

The client MUST NOT enable threshold signing by any path other than the user selecting A on this screen or in settings. Selecting A later from settings shows the same text and the same two-device requirement.

### 7.4 Threshold parameters
- Scheme: FROST per RFC 9591 with the secp256k1 Taproot variant as implemented by `frost-secp256k1-tr` (Zcash Foundation). Concretely: if `pubkey(nsec)` has odd y, the dealer uses `a_0 = n − nsec` so the group key is even-y; group nonce commitment parity is handled per that ciphersuite at each signing round. Implementations MUST use that ciphersuite or one interoperable with it. On reconstruction (§7.5a, §7.15) the result is `n − nsec` for an odd-y key; the client MUST re-negate before storing or exporting. ECDH is unaffected because x-only.
- `t = 2`.
- Index `1` is the **server index**. Every enrolled server holds a replica of share 1.
- Index `2` is the **restricted index**. Every restricted-role device holds a replica of share 2.
- Trusted devices hold indices `3..N`, one per trusted `E.pub` in the device list.
- Replicas share an index and therefore never combine: any number of servers is one share; any number of restricted devices is one share. Valid signing pairs are server + restricted, server + trusted, restricted + trusted, trusted + trusted.
- Polynomial at activation:
  ```
  a_0 = nsec (parity-adjusted per above)
  a_1 = random mod n                       // MUST be fresh randomness; never derived from the nsec
  f(x) = a_0 + a_1·x
  share_j = f(j)
  ```
  A deterministic `a_1` would let a re-activation reproduce an old polynomial and resurrect revoked shares; it is forbidden.
- Epoch: `{counter, id}` where `counter` increments and `id` is random 128 bits. A member orders epochs by `counter`. Two honest refreshes racing produce the same `counter` with different `id`s: the **lower `id` wins**; a member that has applied the loser discards that share (it kept the pre-refresh share until both ACKs cleared — see §7.9) and applies the winner; the losing initiator, on seeing the winner, re-initiates on top of it if its purpose (a removal, an exit) is still unmet. Members retain the previous-epoch share until they see an **epoch-finalized marker** (`EPOCH_FINALIZED`, kind 24319, wrapped to members; group-key-signed) listing ACKed indices — or 7 days elapse, or a newer verified epoch supersedes, whichever first; ACKs flow only member→initiator, so the marker is what makes retention observable to everyone else. A re-activation (§7.10) sets `counter = max(any record found, unix_time)` + 1.
- **Epoch record**: kind 30242, `d = "frost"`, encrypted under the group secret (§7.1) with a **plaintext tag `["epoch", counter]`** so a member holding a stale group secret can still tell that a newer epoch exists, content `{epoch, t, group_pub, commitment: a_1·G, members: [{index, E.pub|S.pub, role}]}`, signed by the group key (via FROST once active). `commitment` lets any member verify any share or partial: `share_j·G == group_pub + commitment·j`. It is updated on every refresh (§7.9).

### 7.5 Activation (user chose A)
Performed by the device that chose A, which still holds the nsec. Every device, including this one, receives a share; no device keeps the nsec.
1. Derive epoch-1 polynomial. Compute share 1 and one share per device in the device list.
2. Gift-wrap `KEY_SHARE {epoch: 1, t: 2, index, share, group_pub, lock}` (kind 24305) to each server `S.pub` and each other device `E.pub`; store own share per §2.1.
3. Publish the epoch record (signed with the nsec directly; this device still holds it).
Activation is journaled: the device writes `{stage, epoch, issued: [...]}` per §2.1 before each step and resumes idempotently after a crash — re-sending unACKed shares, re-publishing the record — and performs step 4 only after steps 1–3 are durably complete.
4. Wipe the local nsec **and every synced copy**: delete the `kSecAttrSynchronizable` Keychain item, delete the Block Store record. Write in their place a small synced **threshold marker** `{group_pub, epoch}` so a device restored from platform backup knows to enroll for a share (§2.4) rather than expect a key.
(Blob upload, if a server is being enrolled at the same time, happens in §7.2 step 3 *before* this activation, while the nsec is still present.)

**Where the full key still exists after activation**, stated so §5 does not overclaim:
- On any device that has not yet ACKed the epoch. Such a device holds the nsec and **cannot be revoked by refresh**; removing it from the list only stops future shares. The lock MUST be amber until every device ACKs, and the devices screen MUST mark each non-ACKed device "still holds full key."
- In the §4.2 backup, by design, under the user's password.
- In any §4.1 ncryptsec file or printed QR the user exported before activation; those survive by definition and the activation screen reminds the user they exist.
- On a keep-key device, by the user's explicit choice.

### 7.5a Reconstructing operations
With the §4.2 content-key indirection, changing the backup password and enrolling an additional server re-wrap `CK` on a trusted device and never reconstruct. **Disable (§7.15), and Re-split (§7.11, which is disable + re-activate), are the only reconstructing operations.** It is privileged: one prompt on the device; with two-device approval on (§7.1), also one tap elsewhere. Refresh, joint issuance, share-1 replication, password change, and server enrollment never reconstruct.

`CK` travels to trusted devices in `KEY_SHARE` / `KEY_SHARE_PART` (trusted indices only; never to index 2 or to servers) and is stored per §2.1.

**Keep-key option.** A user MAY mark one device "Keep the full key on this device" in settings. Approval: the same second-trusted-device tap as Offline mode entry (§7.14), with the prompt "*Laptop* wants to keep your full key permanently. Allow?" — required regardless of the two-device-approval setting. That device is a **bunker**: it keeps the nsec, signs alone, and can issue and refresh alone. A bunker **cannot be revoked** — refresh changes shares, not the nsec — and the client says so when the option is chosen. This is off by default.

On receiving `KEY_SHARE`, a device verifies that `group_pub` equals the user's known x-only pubkey **and** `share·G == group_pub + commitment·index`, stores the share per §2.1, wipes its nsec, and gift-wraps `SHARE_ACK {epoch}` (kind 24306) to the activating device's `E.pub`. A device offline at activation keeps its nsec and continues in base mode until it receives its share.

The **lock indicator** is green only when every device in the device list has ACKed the current epoch. Until then it is amber with the count ("2 of 3 devices").

### 7.6 Signing and what the co-signer sees
A FROST co-signer must see the message it signs. **Every event a share-only device signs through the server is visible to the server in plaintext**, including DM envelopes (not their contents, which are NIP-44-encrypted before signing). Trusted-device co-signers see the same. §7.3 discloses this.

- Default: device share + server share. The requester sends the **full unsigned event**, not a 32-byte digest; the co-signer serialises and hashes it itself (NIP-01), so it knows the kind and content it is signing. Every co-signer — server **or trusted device** — MUST check the requester's role before completing a round: for a restricted requester it signs only kinds on an **enumerated allowlist** shipped with the client and server (reference set: 0, 1, 3, 5, 6, 7, **13**, 16, 30023; deployments may extend it deliberately) and refuses everything else — in particular 30242 and 10002. Kind 13 is required: NIP-17 DMs are sent by group-key-signing the *seal* (the 1059 wrap is signed by a one-time key, so 1059 never legitimately reaches a co-signer). Kind 10002 is refused for restricted requesters because rewriting the relay list assists the record-withholding attacks §2.4 and §7.9 defend against. Kind 5 is signed only after checking its `e`/`a` tags: a deletion referencing any kind-30242 coordinate is refused, since it would let an origin destroy the device list or epoch record and manufacture the §2.4 "absence" branch. An allowlist is used because "alters the device list or backup" is not evaluable for future kinds; a denylist here fails open as the ecosystem adds kinds. (§7 rumors are sealed by `E`, not the group key, so a co-signer never sees or signs them; the guard for those is §7.9 step 4(a).) `/v1/sign` and the relay path both carry the requester's `E.pub` signature so this can be applied. Requests and rounds are gift-wrapped between `E.pub` and `S.pub` over relays or `<url>/v1/sign` over HTTPS; both MUST be supported, HTTPS tried first.
- Server unreachable (timeout 5 s on all replicas): the client tries any trusted device in the list — a keep-key or Offline-mode device first, since those need no round — over relays, LAN (QRST §11.7), or BLE (native apps only; the same single-message wrap bytes over a GATT characteristic — profile UUIDs live in an implementation companion, not this spec). Trusted devices and servers complete rounds for **trusted** members silently (§2.2). A trusted device completes rounds for a **restricted** requester only if it has itself probed every enrolled server in the last 60 s and none answered; otherwise it refuses with "use the server," so a site cannot route around the server's audit by asking a phone instead. With **zero servers enrolled** the condition is vacuously satisfied by design: trusted devices are then the normal co-signers for everyone. Trusted co-signers keep the same per-requester log and apply the same alert rule as servers (§7.13). A restricted device completes a *signing* round only for a **trusted** requester and only for kinds 30242 and ordinary content, as a last resort when no server or trusted device answered; it never completes rounds for restricted requesters and never ECDH for anyone. This is what lets the minimum §7.3 configuration (one trusted device, one browser, one server) remove a compromised server: the phone initiates the refresh, the browser co-signs the epoch record. The requesting client shows **"Signing via *Phone*…"**.
- Nothing reachable: the draft is kept as an unsigned rumor with `created_at` fixed at compose time and signed at the first opportunity. The client shows **"Will post when your server or another device is reachable."** For local-only relays, the client points to Offline mode (§7.14).

### 7.6a Decryption (DMs and gift wraps)
FROST produces signatures only. NIP-04/NIP-44 conversation keys and NIP-59 seal decryption need `ECDH(nsec, P) = nsec·P`, so a share-only device cannot decrypt alone. Threshold ECDH is one round:

```
Requester (index d) → co-signer (index c):  { P }                     wrapped to E.pub / S.pub, or /v1/ecdh
Co-signer → requester:                      { λ_c·s_c·P }         after verifying P is on-curve and not the identity. (Each partial is a static-DH answer whose aggregate targets the *group* key, which refresh never changes — so the §7.13 hard ceiling, not refresh, is the control; at those query counts Cheon-style attacks on secp256k1 remain impractical.)
Requester:                                  nsec·P = λ_d·s_d·P + λ_c·s_c·P
```
The **requester aggregates**; the co-signer never learns `nsec·P`, only `P` and its own partial. Consequences, which §7.3 discloses:
- Reading DMs and unwrapping NIP-59 gift wraps on a share-only device requires a co-signer reachable, exactly like posting. Clients SHOULD batch: one round can carry many `P` values.
- The co-signer learns which `P` values the user is deriving keys for — for NIP-04/44 that is the peer's pubkey (DM metadata); for NIP-59 wraps it is a random one-time key (nothing).
- Keep-key and Offline-mode devices decrypt alone.
- The role rules apply: restricted devices may request; trusted devices and servers respond; restricted devices never respond to ECDH.

### 7.7 Adding a device after activation (joint issuance)
QRST Flow A or B runs unchanged through the code-entry step (QRST §9). The Receiver's index `j` is `2` if its role is restricted, otherwise the next unused index ≥ 3. Instead of one `KEY_TRANSFER`, the Receiver receives two `KEY_SHARE_PART` (kind 24307) wraps for `j`:
```
Sender device (index h):  r ← random mod n
                          sends Receiver:  λ_h(j)·s_h − r
                          sends Server:  r          (wrapped to S.pub)
Server (index 1):         sends Receiver:  λ_1(j)·s_1 + r     (wrapped to the Receiver's burner `J.pub` from the QR, which the Sender forwards with `r`)
Both parts also carry:    group_pub, commitment, epoch, group_secret   (so a fresh Receiver can verify without first reading the encrypted epoch record)
Trusted Receiver only:      CK rides in the trusted helper's part — servers never hold CK (§7.5a)
Receiver:                   share_j = sum of the two parts; verify share_j·G == group_pub + commitment·j, derive npub from group_pub, show "Log in as @name?" (a first-time Receiver has no prior pubkey to compare) — Yes → store
```
If the server is unreachable, any second **trusted** online device plays the server's role with its own index. Helpers are trusted devices and servers only; a restricted device MUST NOT act as Sender or helper. The Receiver ACKs; the Sender updates the device list and epoch record.

### 7.8 Adding a server replica
Same as §7.7 with `j = 1`. Alternatively an existing server, on a gift-wrapped instruction from a device, wraps share 1 directly to the new server's `S.pub`. Either path is one QR scan for the user.

### 7.9 Refresh (one tap; replaces rotation)
Triggered from settings ("Rotate keys") on a trusted device, and automatically on device removal, Offline-mode exit, and after §7.10 recovery. No share is released and nothing is reconstructed.

1. The initiating trusted device picks random `r` mod n and sets `epoch + 1`. It first obtains a group signature over the new epoch record with **old** shares (it and a co-signer, before any delta is applied), so the record can be signed while everyone still shares a polynomial.
2. It gift-wraps `KEY_REFRESH {epoch, delta: r·j}` (kind 24309) to each member `j` still on the list (one wrap per replica, same `delta` for replicas of one index), (its own delta is applied in step 3).
3. It publishes the already-signed epoch record with `commitment' = commitment + r·G` and the new group secret, then applies `r·own_index` to its own share.
4. Each member verifies (a) the wrap's seal is signed by a **trusted** `E.pub` present on the member's current device list, and (b) `(share + delta)·G == group_pub + commitment'·j`; only then replaces its share and ACKs (kind 24306). Device-list updates MUST be published before any refresh wrap that depends on them. A member whose list does not contain the sender first re-fetches the list (once, up to 5 minutes) before deciding; a `KEY_REFRESH` still failing (a) MUST be discarded and MUST raise the red lock state ("a refresh was attempted by *example.com*").

The group key is unchanged. Old shares are on a different polynomial and cannot combine with new ones. A removed member is simply not sent a delta. Members that miss the wrap receive it when next online (wraps live 30 days, §7.17, subject to relay retention — clients SHOULD publish §7 wraps to at least one relay the user controls or pays for); until then they cannot sign and the lock shows amber. A member holding shares from two epochs MUST discard the older once the newer verifies.

**Removing a restricted device.** All restricted devices share index 2, so a hostile origin with two browsers enrolled keeps share 2 if only one is removed. Removal is therefore **per origin**: removing a site removes every restricted entry with that origin, and the delta for index 2 goes only to surviving origins. (Sending survivors a delta is fine: an honest survivor does not leak `r` to a removed device, and a hostile one already held the share.)

**Refresh war.** A compromised trusted device can refresh with itself and a server as the only members, excluding the rest; another trusted device can do the same back. There is no in-protocol resolution. The resolution is §7.10 recovery from the backup on a clean device, followed by re-activation with a list that excludes the compromised device.

The initiator learns nothing about any other member's share. Note that `delta = r·j` with `j` public, so **every member learns `r`**, and a removed member's old share plus `r` is a valid new share. This has a lasting consequence: **a share from any past epoch, plus every `r` since, is a current share** — and every current member has seen every `r`. So a lost trusted device's stale share stays dangerous forever to any current member that obtains it, including a hostile site, silently and without the server. Refresh cannot fix this at `t = 2` with linear deltas. The fix is **Re-split** (§7.11): disable and re-activate in one flow, which draws a fresh random `a_1` and severs the algebraic link to every old share. The client recommends Re-split, not refresh, when the removed member is a trusted device that may have been lost rather than merely retired. Only trusted devices may initiate; servers and restricted devices never do, and members enforce this per step 4(a). An epoch record is authoritative only if it is accompanied by a `KEY_REFRESH` (or `KEY_SHARE` at activation) that passed step 4(a); a kind-30242 event on its own is not trusted. §7.6's refusal and this rule are deliberately redundant: the first stops an honest server from helping, the second stops a dishonest one from mattering.

### 7.10 Recovery (all devices lost)
1. New device (native app; a browser MUST NOT offer recovery): enter server URL and backup password (or scan a server QR that carries the URL). A user who has forgotten the URL MAY have opted, at enrollment, to publish a plaintext `["backup-hint", "<url>"]` tag on the device list (off by default; it tells the world where to aim online guesses, per §4.2).
2. Recover per §4.2 (password proof, rate-limited) → backup blob. Decrypt locally (roughly one to three seconds at `log_n = 18`, 256 MiB).
3. The device now holds the nsec in base mode. The client MUST then prompt to **change the backup password** (re-running §4.2 setup) and MUST offer to **drop or replace the server** it just recovered from, since a compromised server is a common reason to be recovering. No server is re-enrolled automatically.
4. If the epoch record shows threshold mode was on, the client offers to re-activate (§7.5) with a fresh epoch and the new device list; old members are excluded because they are not on it, and only servers the user kept in step 3 receive share 1.

### 7.11 Device removal
Settings → device → **Remove**. In threshold mode the client asks: **"Do you still physically control this device, and was it wiped?"** Yes → retired. No or unsure (lost, stolen, sold, traded in) → lost, the default; extractable storage on a sold device is "lost" in every way that matters. Retired → refresh (§7.9) with the device excluded. Lost (default) → **Re-split**: §7.15 disable and §7.5 re-activation as one journaled operation on a trusted device (reconstructing, privileged, subject to two-device approval), which makes the lost device's share algebraically useless rather than merely stale. Restricted removal is per origin (§7.9). A bunker device cannot be revoked this way (§7.5); the client says so. In backup-only mode the label reads "Forget device (its copy of your key is not affected)" per §3.2.

### 7.12 Server compromise
Attacker obtains share 1 and the backup blob. Share 1 alone signs nothing. The blob is protected by the password at `log_n = 18`; its strength is the user's choice per §7.2. By the spec's own algebra (§7.9), a plain refresh cannot revoke a share that has already been exfiltrated: the dumped share 1, plus the stream of future `r` values that every current member sees, remains a current share — and a hostile restricted origin that obtains the dump can then reconstruct silently. The remedy is therefore **Remove server + Re-split** (§7.11): exclude the server, then disable-and-reactivate with a fresh random `a_1`, severing the algebraic link to the stolen share. The client performs Re-split, not refresh, for server compromise whenever any restricted device is enrolled, and recommends it even when none is. It then prompts to change the backup password (a `CK` re-wrap, §7.5a) and to delete the blob on the removed server.

**Blob and share 1 on one host.** In threshold mode a compromised server holding both, plus a weak password, is the key — undercutting "no server holds a usable key" for exactly the users who chose weak passwords. The client MUST offer, at second-server enrollment, to place the blob on a different host than share 1 ("Keep backup and signing on separate servers"), and MUST offer at first enrollment a generated recovery phrase (six PGP words, ~96 bits) as the password, pre-filled and editable. Neither is required; the §7.2 warning line stays.

### 7.13 Hostile restricted device
A hostile site holds share 2. Alone it signs nothing. With the server it can sign — as can any enrolled device — and this is visible to the server and revocable by refresh. It cannot: combine with other sites (same index); act as Sender or helper; request share 1; enter Offline mode, keep-key, or disable without a tap on a trusted device that names it and the consequence; or see a backup-password field (from honest code — see the phishing path below). Holding the group secret, it **can read the device list and epoch record**: device count, roles, `E.pub`s, and user-written labels ("Dana's laptop") — metadata a phishing page can weaponize for convincing prompts. Its worst case is **posting as the user and reading every DM the user has ever received** (via §7.6a ECDH with the server) until it is removed — **plus a phishing path to the full key**: the hostile origin *is* the client on that device, so "MUST NOT present a backup-password field" binds honest code only. A pixel-perfect "confirm your backup password" dialog, plus the user's npub and a knowable server URL, is the key via `/v1/recover` — the site gets the password right, not guessed, so rate limits don't apply. This cannot be prevented in-protocol; it is bounded by the recovery delay (§4.2), which makes the theft visible and cancellable from any trusted device, and softened by the generated six-word phrase: a user who kept it has only ever typed it on a trusted device, so a website asking for it reads as wrong. Stated as residual risk in §5. It cannot enter Offline mode at all (§7.14).

**Audit surface.** Every co-signer (server or trusted device) keeps a per-requester log of signing and ECDH rounds (kind, timestamp, peer pubkey for ECDH) and sends it to trusted devices as a daily `AUDIT_DIGEST` wrap (24317; alerts are 24318); the devices screen shows it per device. A server MUST notify trusted devices when index 2's ECDH peer count or signing rate in the last hour exceeds both an absolute floor (25 distinct ECDH peers, or 50 signatures, in an hour) and five times its trailing-week hourly median ("*example.com* is decrypting your DMs in bulk — remove it?"). During the first 24 hours after an origin's enrollment the same thresholds produce a differently worded, non-alarming notice ("*example.com* just synced *N* conversations") rather than silence — the first sync is exactly when a hostile site would read everything, and the user should see that it happened. Rate alerts alone can be boiled slowly, so there is also a **cumulative cap** — sized against NIP-59 mechanics: every incoming gift wrap uses a fresh random ephemeral key, so one-shot `P`s are ordinary mail, while **recurring `P`s (seen in two or more rounds) are conversation keys**, and a burst of them is the signature of a bulk history read. The cap counts only recurring `P`s: co-signers refuse ECDH for a restricted origin beyond 200 distinct *recurring* peers per rolling 7 days; exceeding it requires a one-tap raise on a trusted device ("*example.com* wants to read more of your conversation history"). Never-repeating `P`s are bounded by the hourly ceiling alone. The **hard ceiling** is 500 ECDH responses per hour per requester, counted **per `P`** (a batch of n peers consumes n), bounding the §7.6a static-DH oracle quantitatively. Users MAY disable DM decryption for restricted devices entirely in settings ("Websites can read DMs" toggle, default on).

### 7.14 Offline mode (a trusted device temporarily holds a threshold)
UI label: **Offline mode**. A toggle in every **trusted** device's settings. Never required for any function. Not available to restricted devices: two shares at `t = 2` is the key, and a device that has held the key cannot be un-given it by refresh — so granting Offline mode to a website would be granting it the key permanently. The toggle on a restricted device is shown disabled with "Not available in a browser."
- **Enter.** The toggle sends an `OFFLINE_REQUEST` to every other trusted device in the list. The user taps **Allow** on any one of them — a trusted device, never a server. The prompt names the requester by its Sender-set label and states the consequence in one line: **"*Laptop* wants to hold your full key offline. Allow?"** That device and the server (or a third trusted device) then jointly issue the requesting device a second index, taken from the trusted range `≥ 3` (§7.7). The epoch record gains `offline: {index_pair, E.pub, since}`. The toggle explains: "Needs a tap on one of your other devices. Turn this on before you go offline."
- **While on.** The device signs and decrypts alone with its two shares.
- **Exit.** The device runs a refresh (§7.9) as initiator and discards its second index, sending no delta for it. No other device's *approval* is required, but relays (or LAN/BLE reach to the members) are: the deltas must be delivered, so exit completes when the device is back in contact. The discarded share is on the old polynomial and dead by construction. The device is **trusted to have discarded** the reconstructable key — this is the same trust already placed in it as a trusted device, and it is why the mode is trusted-only.
- Any trusted device may end a *cooperative* device's Offline mode by refreshing without a delta for the second index. Against a **suspect** device this is a no-op: the target keeps its primary membership, receives its primary delta, learns `r` from it, and can update the retained second share. Ending Offline mode for a device you no longer trust is therefore **Re-split** (§7.11, "lost"), same as any other suspect trusted device.

### 7.15 Disabling threshold signing
Settings → "Turn off threshold signing." Available only on trusted devices. This is the one operation that reconstructs the nsec: the device collects one other share (a server releases share 1 to a trusted requester; with two-device approval on, only with an `APPROVAL`), then:
0. **Pre-refresh.** Before reconstructing, the client runs one §7.9 refresh whose member set is only the trusted devices and unflagged servers — every restricted origin (and any server the user flags on the disable screen) is excluded and receives no delta. Their shares are now on a dead polynomial *by construction*, not by their cooperation, before deletion is even requested. Then the device collects one other share, reconstructs, and **durably stores the nsec per §2.1 before anything else** — a crash after members delete but before the key is stored would otherwise be unrecoverable in a serverless deployment with no export on file.
1. Wraps `DISABLE {epoch}` (kind 24314, 30-day TTL) to every member, and publishes the epoch record marked `disabled` with a plaintext `["epoch", counter]` tag. **Servers MUST delete share 1 and every member MUST delete its share, `CK`, and the group secret** on receiving a `DISABLE` whose seal is from a trusted `E.pub` on the current list — and, when two-device approval is on, whose attached `APPROVAL` verifies; without it members MUST NOT delete, or a single compromised trusted device gets a remote wipe that bypasses the setting. For the remaining (trusted + server) members, deletion is what kills the final-epoch shares; the pre-refresh in step 0 already ensured that no share outside that set survives algebraically, so a website that never processes the notice holds nothing.
2. Each trusted device replies `DISABLE_ACK` (kind 24315) carrying a fresh burner. The initiator wraps `KEY_TRANSFER` to **that burner** with the QRST §11.4 600 s TTL — never to `E.pub`, so no nsec ciphertext is ever addressed to a long-lived key on a relay.
3. Restricted devices are **not** sent the key by default — the screen lists them and lets the user tick any to include (those also go via a burner); the rest re-enroll by transfer (QRST) when next used. A trusted device that misses the 600 s window comes back to a `disabled` record with its share deleted; it shows the Receiver QR and re-enrolls by transfer (QRST) from any device that now holds the key. Trusted devices store the nsec per §2.1 on receipt. Re-enabling is §7.5.

### 7.16 Lock indicator
Shown in settings and on the compose screen. Every state has a distinct **shape**, a distinct **colour**, and a **text label always adjacent**; colour is never the only channel.

| State | Colour | Glyph | Label |
|---|---|---|---|
| Split (default) | Green | Closed lock with checkmark | "No single device holds your key" |
| Keep-key | Green | Closed lock with phone silhouette | "Full key on *Phone*; other devices hold pieces" |
| Offline mode | Blue | Closed lock with single-figure badge | "Offline mode on *Laptop* since *date* — tap to end" |
| Pending | Amber | Half-open lock with three dots | "Waiting for *N* devices" |
| Flagged | Red | Lock with exclamation | "Rotate recommended: *reason*" |
| Off | Grey | Open outline lock | "Threshold signing off" |

Glyphs MUST remain distinguishable at 16 px in monochrome. The indicator is informational; it MUST NOT emit notifications or block any action.

### 7.17 Rumor kinds (complete list)

Transfer kinds are defined in QRST §11.4 and are not repeated here. These are
this document's own.

| Kind | Name | Direction |
|---|---|---|
| 24305 | KEY_SHARE | issuer → member |
| 24306 | SHARE_ACK | member → issuer |
| 24307 | KEY_SHARE_PART | helper → Receiver (§7.7) |
| 24308 | OFFLINE_REQUEST | requester → trusted devices |
| 24309 | KEY_REFRESH | initiator → member |
| 24311 | APPROVAL | second trusted device → server / helper (§7.1) |
| 24314 | DISABLE | initiator → member (§7.15) |
| 24315 | DISABLE_ACK | trusted member → initiator, carries a fresh burner (§7.15) |
| 24316 | RECOVERY_NOTICE | server → registered devices (§4.2) |
| 24317 | AUDIT_DIGEST | co-signer → trusted devices (§7.13) |
| 24318 | ALERT | co-signer → trusted devices (§7.13) |
| 24319 | EPOCH_FINALIZED | initiator → members (§7.4) |

All placeholders. 24301–24304, 24310, 24312 and 24313 are no longer used by this
document; the transfer messages that occupied them are QRST 24401–24407.

All are sealed and wrapped exactly as QRST §11.4 specifies, with one difference:
**§7 wraps use `expiration = now + 30 days`**, not the ten-minute transfer TTL,
so offline members can still receive them. A member offline longer than 30 days
misses the wrap; on return it finds a newer epoch record than its share and
re-enrolls via joint issuance (§7.7), which any trusted device can do from the
devices screen.

## Appendix A — References
NIP-07, NIP-44, NIP-49, NIP-59. RFC 9591 (FROST). BIP-340. Transfer: [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md).
