# Capability Map: KeyCourier

| Module id | Responsibility | Depends on |
|---|---|---|
| `request-contract` | Validate content-free agent requests and receipts | - |
| `local-vault` | Store secret material in the macOS data-protection Keychain | `request-contract` |
| `approval-app` | Present and approve requests in a native SwiftUI app | `request-contract`, `local-vault` |
| `local-delivery` | Install approved values into allowlisted local consumers | `request-contract`, `local-vault` |
| `client-cli` | Let Codex, Claude Code and OpenCode submit and inspect requests | `request-contract` |
| `guided-destinations` | Map simple Mac Mini and VPS names to stable secret, consumer and target IDs | `request-contract` |
| `remote-delivery` | Encrypt and deliver approved packages to reviewed host agents | `request-contract`, `local-vault`, `local-delivery` |

Build order: `request-contract` -> `local-vault`, `client-cli`, `guided-destinations` -> `approval-app`, `local-delivery` -> `remote-delivery`.

The first verified release covers every module except live `remote-delivery`. The remote protocol, age/SSH adapters, replay store and host-side atomic receiver are covered by injected dummy tests, but no host is modified until the owner reviews the host plan and each dummy-secret canary passes.
