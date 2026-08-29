# KeyCourier security policy

## Report a problem

Do not include a credential, environment dump, Keychain record, private key or ciphertext payload in an issue. Report the affected component, expected boundary and a reproduction using only `dummy-not-a-real-secret`.

Use [KeyCourier Support](https://keycourier.drewsdigest.com/support/) for private coordination. Public source issues are suitable only for content-free reproductions. If a report could expose another user, credentials or a live system, do not post it publicly.

## Invariants

- Plaintext never leaves the KeyCourier process except for an owner-approved write to the exact allowlisted consumer.
- Agent requests and receipts contain identifiers and status only.
- Secret metadata files never contain a secret value.
- Destination files, metadata, requests, receipts and rollback copies are owner-only.
- Unknown consumers, target mismatches, expired requests, unsafe files and unconfigured remote targets fail closed.
- Expired credentials fail before Keychain access or destination installation.
- An iPhone decision is accepted only when its signature and request digest match the Mac-signed summary shown to the owner.
- The app never uses model-provided text as the system authentication prompt.
- Remote delivery must use a distinct per-host recipient and must pass a dummy-secret consumer canary before live use.

## Out of scope

- Protection after compromise of the logged-in macOS account
- Authentication of one local AI client process versus another
- Protection provided by a sandboxed Mac App Store edition; the automation edition is distributed with Developer ID.
- Live Mac Mini or VPS delivery before their host agents and owner-approved dummy canaries are verified.
- Security guarantees for unofficial builds, modified binaries or unsupported operating systems.
