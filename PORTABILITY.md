# Portability and clean-clone hand-off

This file records how to resume work from another computer without relying on this Mac's caches, worktrees or credentials. It is a hand-off, not evidence that a deployment, account, device or release is healthy.

## Authority and status

- Repository: `DrewMauldin/KeyCourier-OpenCore` (public)
- GitHub description: No GitHub description is set.
- Default branch on 2026-08-30: `main`
- Recorded default head: `b22f4c969309f8e42873c3559f27f98152cd89d7`
- Last GitHub push reported: `2026-08-29T05:13:29Z`
- Current status: The GitHub default branch is the clean-clone baseline. Open pull requests below are not part of that baseline until reviewed and merged.

## Clean-clone setup

```sh
git clone https://github.com/DrewMauldin/KeyCourier-OpenCore.git
cd KeyCourier-OpenCore
xcodegen generate --spec project.yml
```

Detected toolchain and lock points:

- Python 3
- XcodeGen
- Xcode
- POSIX-compatible shell for tracked shell scripts

If a required version is not pinned in the repository, record and pin the working version in a reviewed PR before depending on it for release reproduction.

## Worktree workflow

Keep the default checkout on the default branch and make each issue or PR in its own sibling worktree:

```sh
git fetch origin --prune
git worktree add ../worktrees/123-short-slug -b fix/123-short-slug origin/main
git -C ../worktrees/123-short-slug status --short --branch
# Commit and push from the worktree, then open a PR. Do not merge from the local default checkout.
git worktree remove ../worktrees/123-short-slug
git worktree prune
```

Use one issue-sized concern per worktree. Re-fetch the live base before creation, and never delete a worktree until its branch is pushed and the remote head matches the local commit.

## Configuration and credentials

Tracked configuration surfaces detected:

- `KeyCourier.entitlements`
- `KeyCourierBridge.entitlements`
- `KeyCourierMobile.entitlements`
- `KeyCourierMobileRelease.entitlements`
- `KeyCourierRelease.entitlements`
- `KeyCourierStore.entitlements`
- `KeyCourierStoreRelease.entitlements`
- `project.yml`

GitHub Actions secret names referenced by tracked workflows:

- No `secrets.NAME` references were detected in tracked workflows.

Keep values in the relevant password manager, platform secret store, Keychain or CI settings. Never copy local `.env`, `.dev.vars`, signing material, tokens, private customer data or exported production configuration into Git.

## External systems

- Apple CloudKit or iCloud
- App Store Connect or TestFlight
- GitHub Actions

Repository state proves only source state. Validate account access, deployed configuration, live data, DNS, OAuth, signing, device behaviour and production consumers as separate gates where they apply.

## Verification

Run the applicable checks from a clean clone. Commands are included only when their supporting files or package scripts are tracked:

```sh
xcodebuild -list -project KeyCourier.xcodeproj
git diff --check
```

For native Apple projects, follow this with a real Xcode build, tests on an installed simulator, physical-device behaviour, signing, entitlements and App Store Connect checks. For hosted or automated projects, follow local checks with a bounded live canary and rollback proof. A passing local command is not production proof.

## Open pull requests

No open pull requests were present when this document was generated.

A PR whose base is another PR head is stacked and must be reviewed in that dependency order. Re-read the live PR base and head before rebasing or merging; this snapshot may become stale. Independent PRs have no implied merge order.

## New-computer recovery checklist

1. Restore GitHub and platform account access from the encrypted credential authority.
2. Clone the current GitHub default branch and compare its head with this recorded snapshot.
3. Install the detected toolchain and use tracked lockfiles or generation manifests.
4. Recreate local configuration from names and templates only, sourcing values from the approved secret authority.
5. Run local verification, then validate each external, device and release gate separately.
6. Recreate only the worktrees needed for selected issues or open PRs.
