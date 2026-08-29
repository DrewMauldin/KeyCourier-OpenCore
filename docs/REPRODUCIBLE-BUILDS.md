# Reproducible build evidence

KeyCourier provides repeatable source verification, not bit-for-bit deterministic Apple binaries. Xcode, SDK, signing timestamps, provisioning profiles and notarisation services affect final artifacts.

## Unsigned verification

Run:

```sh
./scripts/verify-release.sh
```

Record the Git commit, clean/dirty source state, macOS version, `xcodebuild -version`, XcodeGen version, test counts and final build results. The verifier builds into ignored local output and performs no upload.

## Signed release manifests

Each archive script captures the clean Git commit and tree before building and
checks that they are unchanged after packaging. It writes a redacted
`RELEASE-MANIFEST.json` beside the artifact containing the source commit/tree,
host and artifact toolchain, target/scheme/configuration/platform,
bundle/version/build, artifact-relative path and SHA-256, signature class and
team, entitlement summary, and notarisation/stapler/Gatekeeper results where
applicable.

The manifest intentionally omits absolute paths, certificate fingerprints and
serials, provisioning-profile identifiers, keychain profile names, credentials
and secret material. Raw Xcode packaging and signature logs may be retained
locally for debugging, but are not release provenance and must not be
published. A release artifact without a matching manifest is historical
evidence only and must be rebuilt before distribution.

## Signed artifacts

Use `scripts/archive-mac-developer-id.sh` for the Automation edition, `scripts/archive-mac-app-store.sh` for the sandboxed Store edition, `scripts/archive-keycourier-bridge.sh` for the separately notarised Bridge, or `scripts/archive-ios-app-store.sh` for iPhone. Preserve the archive, export log, artifact SHA-256, redacted release manifest, inspected entitlements, certificate class and Apple processing result. Never commit signing identities, profiles or notarisation credentials.

A simulator build does not prove device signing, push notifications, production CloudKit or App Store behaviour. A notarised Mac artifact and a processed iPhone build must be tested separately on supported physical devices with dummy credentials.
