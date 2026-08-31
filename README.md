# Nostr Key Transfer & Storage

This spec is a method to send and recieve Nostr secrets by utilizing [QR-codes](https://en.wikipedia.org/wiki/QR_code) and [gift-wrap](https://github.com/nostr-protocol/nips/blob/master/17.md) messages. It can transfer nsec identities, secrets, and relay information with reasonably high security.

The primary purpose of this project is to allow for increased security of key transfer and storage than the typical copy-and-paste method. Security is upgraded where possible, within reasonable constraints, to help keep the user key safe and help the user to avoid needing the copy-paste method. 

It is a tiered system utilizing the most secure method of key management where available first: FROST, iCloud Storage, Google secure sync, secure gift-wrap over public relays, and is compatible with Bluetooth and LAN transfer. It is fully compatible with FROST and can silently upgrade  once paired with a compatible FROST server. When FROST is activated, there are protections from various angles of attack including device compromise and server compromise. Even before FROST is activated, there is strong shoulder surfing resistance. 

Users are made as secure as their preferences allow, so far as the spec is able, and where robust defaults can be chosen automatically without major compromise, they are. 

`This project benefits from more eyes and more implementations. Devs and users are encouraged to pressure test claims made here to ensure reasonable convenience and security can be deployed widely in various hardware and software conditions. Pull requests and issue submissions are welcome.`

## Why this is not NIP-46

NIP-46 is a signing protocol for a remote signer. A remote signer has to be reachable for every single event signature, whereas a device that has received a key under this spec does not until FROST is activated, after which only 2 of N devices are required. 

NIP-46 does not specify a key transfer method nor about how to store it, whether it is backed up, or what happens when the machine is lost. This project is intended to fill some or all of those gaps. 

## Status

Version 8.0-rc1 is a release candidate rather than a finished standard, and
review is more useful right now than implementation, because three things are missing: the event kinds are unregistered placeholders that will change, there are no test vectors for any of the derivations, and Appendix A specifies the constraints on the 64-entry emoji table without containing the table, so the short authentication string is not yet reproducible across implementations. Disagreements and suspected errors belong in [SPEC_ISSUES.md](SPEC_ISSUES.md).
