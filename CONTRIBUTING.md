# Contributing to KeyCourier

KeyCourier accepts small, reviewable changes that preserve its owner-approval and plaintext-exclusion boundaries.

Before opening a change:

1. Use only dummy values such as `dummy-not-a-real-secret` in tests and screenshots.
2. Add or update a test for any trust-boundary behaviour.
3. Run `./scripts/verify-release.sh`.
4. Confirm `git diff --check` is clean.

Never include credentials, private keys, provisioning profiles, environment dumps, Keychain records or live ciphertext in an issue, commit or build log. Security reports follow [SECURITY.md](SECURITY.md).

The generated Xcode project is committed for convenience, but `project.yml` is the project-definition authority. Keep changes surgical and do not reformat unrelated files.
