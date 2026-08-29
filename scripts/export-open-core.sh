#!/bin/bash
set -euo pipefail

# Export the reviewed, public KeyCourier source surface from a committed Git
# object. This script intentionally never reads product files from the working
# tree: the checkout must be clean and git archive is the only source input.

usage() {
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    echo "  OUTPUT_DIRECTORY must not already exist and must be outside the source checkout." >&2
}

if [[ "$#" -ne 1 ]]; then
    usage
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

for required_command in git tar python3; do
    command -v "$required_command" >/dev/null || {
        echo "Open-core export requires $required_command." >&2
        exit 1
    }
done

if [[ "$1" = /* ]]; then
    requested_output="$1"
else
    requested_output="$PWD/$1"
fi

output_name="$(basename "$requested_output")"
output_parent="$(dirname "$requested_output")"
if [[ -z "$output_name" || "$output_name" = "." || "$output_name" = ".." ||
    ! -d "$output_parent" ]]; then
    echo "Output parent must exist and output name must be a directory name." >&2
    exit 64
fi
output_parent="$(cd "$output_parent" && pwd -P)"
OUTPUT_ROOT="$output_parent/$output_name"

case "$OUTPUT_ROOT" in
    "$PROJECT_ROOT"|"$PROJECT_ROOT"/*)
        echo "Refusing to export inside the source checkout: $OUTPUT_ROOT" >&2
        exit 1
        ;;
esac

if [[ -e "$OUTPUT_ROOT" || -L "$OUTPUT_ROOT" ]]; then
    echo "Output directory already exists: $OUTPUT_ROOT" >&2
    exit 1
fi

if ! git -C "$PROJECT_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "Source checkout is not a Git worktree: $PROJECT_ROOT" >&2
    exit 1
fi

if [[ -n "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "Open-core export requires a clean committed checkout." >&2
    exit 1
fi

SOURCE_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --verify HEAD)"
SOURCE_TREE="$(git -C "$PROJECT_ROOT" rev-parse --verify "${SOURCE_COMMIT}^{tree}")"

# This is deliberately an allowlist rather than an archive of the repository.
# Additions to the public mirror therefore require an explicit review here.
ALLOWLIST=(
    ".gitignore"
    "CAPABILITIES.md"
    "CHANGELOG.md"
    "CONTRIBUTING.md"
    "LICENSE"
    "README.md"
    "ROADMAP.md"
    "SECURITY.md"
    "THIRD_PARTY_NOTICES.md"
    "TRADEMARKS.md"
    "project.yml"
    "Design/KeyCourierIcon.png"
    "HostAgent/KeychainAdapter.swift"
    "HostAgent/host_agent.py"
    "HostAgent/tests/test_host_agent.py"
    "Integrations/skills/keycourier"
    "KeyCourier.xcodeproj"
    "KeyCourier.entitlements"
    "KeyCourierBridge.entitlements"
    "KeyCourierMobile.entitlements"
    "KeyCourierMobileRelease.entitlements"
    "KeyCourierRelease.entitlements"
    "KeyCourierStore.entitlements"
    "KeyCourierStoreRelease.entitlements"
    "Sources"
    "Tests/KeyCourierCoreTests"
    "config/release/ExportOptions-AppStore.plist"
    "config/release/ExportOptions-DeveloperID.plist"
    "docs/ACCESSIBILITY-AUDIT.md"
    "docs/ARCHITECTURE.md"
    "docs/CAPABILITY-MAP-1.1-1.6.md"
    "docs/LAUNCH.md"
    "docs/LICENSING.md"
    "docs/PUBLIC-RELEASE-AND-OPEN-SOURCE-STRATEGY.md"
    "docs/REPRODUCIBLE-BUILDS.md"
    "docs/SPEC-1.1-1.6.md"
    "docs/SPEC-delivery.md"
    "docs/SPEC-guided-destinations.md"
    "docs/SPEC-ios-companion.md"
    "docs/SPEC-mac-app-store-bridge.md"
    "docs/SPEC-macos-app.md"
    "docs/SPEC-personal-vault-and-telegram.md"
    "docs/SPEC-production-readiness.md"
    "docs/SPEC-request-contract.md"
    "scripts/archive-ios-app-store.sh"
    "scripts/archive-keycourier-bridge.sh"
    "scripts/archive-mac-app-store.sh"
    "scripts/archive-mac-developer-id.sh"
    "scripts/export-open-core.sh"
    "scripts/install-local.sh"
    "scripts/release-provenance.sh"
    "scripts/verify-release.sh"
)

# Keep generic CI checks when a reviewed workflow directory is present, while
# avoiding a broad .github allowlist that could carry private automation.
if git -C "$PROJECT_ROOT" cat-file -e "$SOURCE_COMMIT:.github/workflows" 2>/dev/null; then
    ALLOWLIST+=(".github/workflows")
fi

for relative_path in "${ALLOWLIST[@]}"; do
    if ! git -C "$PROJECT_ROOT" cat-file -e "$SOURCE_COMMIT:$relative_path" 2>/dev/null; then
        echo "Allowlist path is missing at $SOURCE_COMMIT: $relative_path" >&2
        exit 1
    fi
done

STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/keycourier-open-core.XXXXXX")"
cleanup() {
    if [[ -n "${STAGE_ROOT:-}" && -d "$STAGE_ROOT" ]]; then
        rm -R "$STAGE_ROOT"
    fi
}
trap cleanup EXIT HUP INT TERM

# The archive is generated from the commit object, not the checkout. The
# private runner, deployment scripts, raw remote-delivery plan, metadata,
# tasks, ignored artifacts and Git history are intentionally not pathspecs.
git -C "$PROJECT_ROOT" archive --format=tar "$SOURCE_COMMIT" -- "${ALLOWLIST[@]}" |
    tar -xf - -C "$STAGE_ROOT"

assert_absent() {
    local relative_path="$1"
    if [[ -e "$STAGE_ROOT/$relative_path" || -L "$STAGE_ROOT/$relative_path" ]]; then
        echo "Private path was included in the export: $relative_path" >&2
        exit 1
    fi
}

# Fail closed if any explicitly private path is ever added to an allowlisted
# parent or accidentally generated during export.
assert_absent ".git"
assert_absent "HostAgent/run_cloud_memory_projection.py"
assert_absent "HostAgent/tests/test_run_cloud_memory_projection.py"
assert_absent "scripts/configure-cloud-memory-projection-executor.sh"
assert_absent "scripts/install-host-agents.sh"
assert_absent "docs/REMOTE-DELIVERY.md"
assert_absent "tasks"
assert_absent "metadata"
assert_absent ".releaseArtifacts"
assert_absent ".derivedData"
assert_absent ".auditDerived"
assert_absent "build"
assert_absent "DerivedData"
assert_absent ".install-backups"
assert_absent "Design/IconConcepts"

for ignored_name in \
    ".DS_Store" "*.xcuserstate" "xcuserdata" "*.pem" "*.key" "*.age" \
    "*.sops" ".env" ".env.*" "__pycache__" "*.pyc"; do
    ignored_match="$(find "$STAGE_ROOT" -name "$ignored_name" -print -quit)"
    if [[ -n "$ignored_match" ]]; then
        echo "Ignored artifact was included in the export: $ignored_name" >&2
        exit 1
    fi
done

mkdir -p "$STAGE_ROOT/docs"
cat > "$STAGE_ROOT/docs/REMOTE-DELIVERY.md" <<'EOF'
# Remote delivery protocol

KeyCourier's remote delivery path is a protocol boundary between the owner
application, an approved consumer and a host-local receiver. The receiver is
configured by the owner before a request is accepted; request metadata cannot
choose a host, command, identity, destination or reload action.

The flow is:

1. A consumer submits metadata-only request information.
2. The owner reviews and approves or denies that request.
3. The application encrypts the approved payload for the configured receiver.
4. The receiver validates signatures, expiry, replay state and its allowlist,
   then installs the value atomically for the selected consumer.
5. The receiver returns only a request identifier, selected identifiers, status
   and a content-free result code.

The receiver must keep private keys and plaintext on the configured host. It
must not accept shell commands or secret material on command-line arguments,
and it must never return credential contents to the consumer or language model.

Transport, storage and deployment details are product-specific. The public
source and protocol specifications are the authority for the validation and
cryptographic rules; deployment configuration remains an owner-reviewed gate.
EOF
chmod 644 "$STAGE_ROOT/docs/REMOTE-DELIVERY.md"

# Generate and immediately validate a deterministic content manifest. It
# contains only relative exported paths, hashes and the source commit/tree;
# no checkout, user, host or output path is serialized.
python3 - "$STAGE_ROOT" "$SOURCE_COMMIT" "$SOURCE_TREE" <<'PY'
import hashlib
import json
import os
import stat
import sys

stage_root, source_commit, source_tree = sys.argv[1:]
manifest_path = os.path.join(stage_root, "OPEN_CORE_MANIFEST.json")

def relative_path(path):
    relative = os.path.relpath(path, stage_root)
    if os.path.isabs(relative) or relative == ".." or relative.startswith("../"):
        raise SystemExit(f"absolute or escaping export path: {relative}")
    return relative.replace(os.sep, "/")

files = []
for root, directories, names in os.walk(stage_root):
    directories.sort()
    names.sort()
    for name in names:
        path = os.path.join(root, name)
        if os.path.islink(path) or not os.path.isfile(path):
            raise SystemExit(f"export contains a non-regular file: {relative_path(path)}")
        relative = relative_path(path)
        digest = hashlib.sha256()
        with open(path, "rb") as exported_file:
            for chunk in iter(lambda: exported_file.read(1024 * 1024), b""):
                digest.update(chunk)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        files.append({"path": relative, "sha256": digest.hexdigest(), "mode": format(mode, "04o")})

files.sort(key=lambda entry: entry["path"])
manifest = {
    "schemaVersion": 1,
    "source": {"commit": source_commit, "tree": source_tree},
    "files": files,
}

with open(manifest_path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write("\n")

with open(manifest_path, encoding="utf-8") as manifest_file:
    parsed = json.load(manifest_file)

if parsed.get("source") != {"commit": source_commit, "tree": source_tree}:
    raise SystemExit("manifest source does not match the exported commit/tree")
entries = parsed.get("files")
if not isinstance(entries, list) or not entries:
    raise SystemExit("manifest file list is empty")

manifest_paths = set()
for entry in entries:
    if not isinstance(entry, dict):
        raise SystemExit("manifest contains a malformed file entry")
    relative = entry.get("path")
    if not isinstance(relative, str) or relative in manifest_paths:
        raise SystemExit("manifest contains an invalid or duplicate path")
    if os.path.isabs(relative) or relative == ".." or relative.startswith("../") or "/../" in relative:
        raise SystemExit(f"manifest contains an absolute or escaping path: {relative}")
    if relative == "OPEN_CORE_MANIFEST.json":
        raise SystemExit("manifest must not recursively contain itself")
    path = os.path.join(stage_root, *relative.split("/"))
    if not os.path.isfile(path) or os.path.islink(path):
        raise SystemExit(f"manifest references a missing or unsafe file: {relative}")
    digest = hashlib.sha256()
    with open(path, "rb") as exported_file:
        for chunk in iter(lambda: exported_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if entry.get("sha256") != digest.hexdigest():
        raise SystemExit(f"manifest hash mismatch: {relative}")
    manifest_paths.add(relative)

actual_paths = set()
for root, directories, names in os.walk(stage_root):
    for name in names:
        path = os.path.join(root, name)
        if os.path.basename(path) != "OPEN_CORE_MANIFEST.json":
            actual_paths.add(relative_path(path))
if actual_paths != manifest_paths:
    raise SystemExit("manifest does not cover exactly the exported files")
PY

if [[ -e "$OUTPUT_ROOT" || -L "$OUTPUT_ROOT" ]]; then
    echo "Output directory appeared during export: $OUTPUT_ROOT" >&2
    exit 1
fi
mv "$STAGE_ROOT" "$OUTPUT_ROOT"
STAGE_ROOT=""

file_count="$(python3 - "$OUTPUT_ROOT/OPEN_CORE_MANIFEST.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as manifest_file:
    print(len(json.load(manifest_file)["files"]))
PY
)"
echo "Exported $file_count files from commit $SOURCE_COMMIT (tree $SOURCE_TREE)."
echo "Content manifest: $OUTPUT_ROOT/OPEN_CORE_MANIFEST.json"
