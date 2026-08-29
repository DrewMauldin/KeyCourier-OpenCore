# Capability Map: KeyCourier 1.1 to 1.6

This map records the owner-approved release sequence. Module identifiers are
stable and dependencies point towards earlier releases.

| Module id | Release | Responsibility | Depends on |
|---|---:|---|---|
| `cross-device-delivery` | 1.1 | Encrypted, replay-resistant delivery to allowlisted Mac Mini and VPS consumers | 1.0 custody and request contract |
| `secret-lifecycle` | 1.2 | Rotation, expiry, consumer inventory, revocation, recovery and emergency lock | `cross-device-delivery` |
| `agent-ergonomics` | 1.3 | Diagnostics, identifier-only discovery, aliases, typed failures, deep links and integration updates | `secret-lifecycle` |
| `approval-policies` | 1.4 | Time-bounded, tuple-scoped approvals and multi-destination blast-radius review | `agent-ergonomics` |
| `security-hardening` | 1.5 | Paired clients, tamper evidence, fuzzing, crash recovery, signed distribution and encrypted iPhone approvals | `approval-policies` |
| `provider-integrations` | 1.6 | Direct provider installation and rotation without returning plaintext to models | `security-hardening` |

Build order: `cross-device-delivery` -> `secret-lifecycle` ->
`agent-ergonomics` -> `approval-policies` -> `security-hardening` ->
`provider-integrations`.

## Shared security invariants

- Secret values exist only in an approved entry surface, Keychain or bounded
  process memory.
- Agent requests, approval transports, logs, receipts and audit exports are
  content-free.
- All destinations, adapters, reload actions and provider scopes are created
  by the owner and selected by stable identifiers.
- A request can never provide an arbitrary path, command, host or provider
  operation.
- Expiry, replay protection, least privilege and fail-closed behaviour apply
  at every transport boundary.
- Dummy values prove each exact consumer before production credentials are
  eligible for that path.
