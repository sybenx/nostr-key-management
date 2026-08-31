# Nostr Key Transfer & Storage

This spec is a method to send and recieve Nostr secrets by utilizing [QR-codes](https://en.wikipedia.org/wiki/QR_code) and [gift-wrap](https://github.com/nostr-protocol/nips/blob/master/17.md) messages while maintaining strong shoulder surfing resistance. It describes a method of transfer for nsec identities, relay information, and other secrets with reasonably high security.

The primary purpose of this project is to encourage increased security for key transfer than the typical copy-paste method. under this spec, storage security is upgraded where possible, within reasonable constraints. This is a substantial upgrade to keeping a plain text nsec in a notes file. 

It is a tiered system utilizing the most secure method first: FROST, iCloud Storage, Google secure sync, passcodes, and secure gift-wrap over public relays, and is compatible with Bluetooth and LAN transfer. It is fully compatible with FROST and can silently upgraded to FROST from secure stroage after pairing with a compatible FROST server. When FROST is activated, there are protections from various angles of attack including device compromise and server compromise. 

Users are made as secure as their preferences allow, so far as the spec is able, and where robust defaults can be chosen automatically without major compromise, they are. 

`This project benefits from more eyes and more implementations. Devs and users are encouraged to pressure test claims made here to ensure reasonable convenience and security can be deployed widely in various hardware and software conditions. Pull requests and issue submissions are welcome.`

## Why this is not NIP-46

NIP-46 is a signing protocol for a remote signer. A remote signer has to be reachable for every single event signature, whereas a device that has received a key under this spec does not *need* a second device at all. If FROST is activated, only 2 of N devices are required and special device authorizations in the spec allow for fully offline signing from a single device. 

NIP-46 does not specify a key transfer method nor about how to store it, whether it is backed up, or what happens when the machine is lost. This project is intended to fill some or all of those gaps. 

# What this project is not

I do not intend to implement this spec directly here or elsewhere. This spec is meant as a reference for other implementations to follow. 

## Status

Version 8.0-rc1 is a release candidate rather than a finished standard. Three things are missing: the event kinds are unregistered placeholders that may change, there are no test vectors for any of the derivations, and Appendix A specifies the constraints on the 64-entry emoji table without containing the table, so the short authentication string is not yet reproducible across implementations. Disagreements and suspected errors belong in [SPEC_ISSUES.md](SPEC_ISSUES.md).
