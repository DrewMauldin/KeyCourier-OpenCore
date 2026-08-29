# KeyCourier architecture decision

## Problem

AI clients need a frictionless way to request credential provisioning, but they share the owner's user context and cannot be trusted with plaintext or arbitrary destination authority. The macOS app must therefore own secret entry, policy, approval and delivery while exposing only a narrow metadata interface.

## Candidate A: atomic request inbox

Caller usage:

```sh
keycourier request --client codex --destination vps \
  --reason "Configure an approved deployment"
keycourier status REQUEST_ID
```

The built-in shortcut expands to stable, content-free identifiers. Custom destinations retain the explicit `--secret-id`, `--target` and `--consumer` form.

Shape:

- CLI validates and atomically writes a bounded `SecretRequest` JSON file.
- The app reads the inbox, joins the request to owner-created secret and consumer metadata, and performs one approval use case.
- A receipt store exposes only status and content-free diagnostic codes.
- Directories are mode 700 and files mode 600.

Failure behaviour: malformed, expired, duplicate or unknown-version requests fail closed. A client can flood its own user account's inbox, so V1 caps pending request count and file size.

## Candidate B: XPC or Unix-socket broker

Caller usage would be identical, but the CLI would connect to a long-running service. This provides immediate delivery and better backpressure. It does not authenticate Codex versus Claude because every client still reaches the broker through the same CLI, and it adds listener lifecycle, code-signing and connection-security complexity before the core approval path is proven.

## Synthesis decision

Use Candidate A for V1. It has the smaller public surface, no network listener, deterministic persistence and simpler recovery. Keep the request types transport-independent so a signed XPC transport can replace the inbox without changing callers.

## Trade-offs accepted

- Accept short polling latency in exchange for no listener or daemon.
- Accept claimed client identity in exchange for a client-neutral CLI; every privileged action still requires owner approval.
- Accept an unsandboxed personal build in exchange for owner-approved file destinations and remote connectivity. Destination allowlists remain the application security boundary.

## Alternatives rejected

- Direct agent Keychain reads expose plaintext to the agent process and model context.
- A hosted vault adds an unnecessary external trust boundary and ongoing infrastructure.
- A custom cross-platform encryption protocol creates avoidable cryptographic risk; remote delivery will use age.

## Verification

- Pure contract and policy tests
- Temporary-directory persistence and dotenv integration tests
- Native app and CLI builds
- Dummy-secret Keychain and approval canary
- Separate per-host remote canaries before live use

## Remote delivery boundary

The remote path keeps the CLI and local inbox unchanged. After owner approval,
`RemoteAgeSecretInstaller` resolves a request's consumer ID through an
owner-created `RemoteAgeAllowlist`; the request cannot select a host alias,
recipient, path or variable. The package payload is encrypted with the
established `age` command before the fixed SSH transport sends it.

The host receiver validates package metadata and expiry, claims the request ID
in a mode-600 replay marker, decrypts with a host-local identity, and reuses the
atomic dotenv installer with one protected rollback copy. It returns a
content-free receipt only. There is no arbitrary command/path channel and no
private-key distribution.

The protocol and receiver are covered by injected dummy tests. Mac Mini and
VPS helper installation, recipient generation and real-consumer canaries remain
explicit owner-review gates; see [remote delivery plan](REMOTE-DELIVERY.md).
