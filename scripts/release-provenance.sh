#!/bin/bash

# Shared release provenance helpers. This file is sourced by the archive
# scripts and intentionally records only public, content-free build evidence.

provenance_capture_source() {
    local project_root="$1"

    KC_PROV_PROJECT_ROOT="$project_root"
    KC_PROV_SOURCE_COMMIT="$(git -C "$project_root" rev-parse --verify HEAD)"
    KC_PROV_SOURCE_TREE="$(git -C "$project_root" rev-parse --verify HEAD^{tree})"
    KC_PROV_SOURCE_STATUS="$(git -C "$project_root" status --porcelain --untracked-files=all)"
    if [[ -n "$KC_PROV_SOURCE_STATUS" ]]; then
        echo "Release archives require a clean committed checkout." >&2
        return 1
    fi

    command -v python3 >/dev/null || {
        echo "Python 3 is required to write release provenance." >&2
        return 1
    }

    KC_PROV_MACOS_VERSION="$(sw_vers -productVersion 2>/dev/null || true)"
    KC_PROV_MACOS_BUILD="$(sw_vers -buildVersion 2>/dev/null || true)"
    KC_PROV_XCODE_VERSION="$(xcodebuild -version 2>/dev/null | sed -n '1p' || true)"
    KC_PROV_XCODE_BUILD="$(xcodebuild -version 2>/dev/null | sed -n '2p' | awk '{print $3}' || true)"
    if command -v xcodegen >/dev/null 2>&1; then
        KC_PROV_XCODEGEN_VERSION="$(xcodegen version 2>/dev/null || true)"
    else
        KC_PROV_XCODEGEN_VERSION="unavailable"
    fi
    KC_PROV_SWIFT_VERSION="$(swift --version 2>/dev/null | sed -n '1p' || true)"
    KC_PROV_MACOS_SDK="$(xcrun --sdk macosx --show-sdk-version 2>/dev/null || true)"
    KC_PROV_IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || true)"
}

provenance_capture_build_context() {
    KC_PROV_TARGET="$1"
    KC_PROV_SCHEME="$2"
    KC_PROV_CONFIGURATION="$3"
    KC_PROV_PLATFORM="$4"
}

provenance_verify_source_unchanged() {
    local project_root="$1"
    local current_commit
    local current_tree
    local current_status

    current_commit="$(git -C "$project_root" rev-parse --verify HEAD)"
    current_tree="$(git -C "$project_root" rev-parse --verify HEAD^{tree})"
    current_status="$(git -C "$project_root" status --porcelain --untracked-files=all)"
    if [[ "$current_commit" != "$KC_PROV_SOURCE_COMMIT" ||
        "$current_tree" != "$KC_PROV_SOURCE_TREE" ||
        -n "$current_status" ]]; then
        echo "Release source changed while the archive was being produced." >&2
        return 1
    fi
}

provenance_notary_field() {
    local notary_json="$1"
    local field="$2"

    KC_PROV_NOTARY_JSON="$notary_json" python3 - "$field" <<'PY'
import json
import os
import sys

try:
    payload = json.loads(os.environ["KC_PROV_NOTARY_JSON"])
    value = payload[sys.argv[1]]
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)

if not isinstance(value, (str, int, float, bool)):
    raise SystemExit(1)
print(value)
PY
}

provenance_write_manifest() {
    local artifact_root="$1"
    local artifact_path="$2"
    local target="$3"
    local scheme="$4"
    local configuration="$5"
    local platform="$6"
    local info_plist="$7"
    local signing_class="$8"
    local team_id="$9"
    local signing_status="${10}"
    local entitlements_summary="${11}"
    local notarization_status="${12}"
    local notarization_submission_id="${13}"
    local stapler_status="${14}"
    local gatekeeper_status="${15}"

    [[ "$target" == "$KC_PROV_TARGET" &&
        "$scheme" == "$KC_PROV_SCHEME" &&
        "$configuration" == "$KC_PROV_CONFIGURATION" &&
        "$platform" == "$KC_PROV_PLATFORM" ]] || {
        echo "Release manifest build context does not match the captured build context." >&2
        return 1
    }

    [[ -f "$artifact_path" ]] || {
        echo "Cannot record provenance for missing artifact: $artifact_path" >&2
        return 1
    }
    [[ -f "$info_plist" ]] || {
        echo "Cannot record provenance for missing app Info.plist: $info_plist" >&2
        return 1
    }

    local artifact_sha256
    artifact_sha256="$(shasum -a 256 "$artifact_path" | awk '{print $1}')"
    local manifest_path="$artifact_root/RELEASE-MANIFEST.json"
    local relative_artifact
    relative_artifact="$(python3 - "$artifact_root" "$artifact_path" <<'PY'
import os
import sys

root = os.path.realpath(sys.argv[1])
artifact = os.path.realpath(sys.argv[2])
relative = os.path.relpath(artifact, root)
if relative == ".." or relative.startswith("../") or os.path.isabs(relative):
    raise SystemExit("artifact must be inside its release artifact root")
print(relative)
PY
)"

    local entitlements_json
    entitlements_json="$(printf '%s' "$entitlements_summary" | python3 -c 'import json, sys; print(json.dumps([part.strip() for part in sys.stdin.read().split(",") if part.strip()]))')"

    KC_PROV_ARTIFACT_SHA256="$artifact_sha256" \
    KC_PROV_ARTIFACT_RELATIVE="$relative_artifact" \
    KC_PROV_CONFIGURATION="$configuration" \
    KC_PROV_ENTITLEMENTS_JSON="$entitlements_json" \
    KC_PROV_GATEKEEPER_STATUS="$gatekeeper_status" \
    KC_PROV_INFO_PLIST="$info_plist" \
    KC_PROV_MANIFEST_PATH="$manifest_path" \
    KC_PROV_NOTARIZATION_STATUS="$notarization_status" \
    KC_PROV_NOTARIZATION_SUBMISSION_ID="$notarization_submission_id" \
    KC_PROV_PLATFORM="$platform" \
    KC_PROV_SCHEME="$scheme" \
    KC_PROV_SIGNING_CLASS="$signing_class" \
    KC_PROV_SIGNING_STATUS="$signing_status" \
    KC_PROV_STAPLER_STATUS="$stapler_status" \
    KC_PROV_TARGET="$target" \
    KC_PROV_TEAM_ID="$team_id" \
    KC_PROV_SOURCE_COMMIT="$KC_PROV_SOURCE_COMMIT" \
    KC_PROV_SOURCE_TREE="$KC_PROV_SOURCE_TREE" \
    KC_PROV_MACOS_VERSION="$KC_PROV_MACOS_VERSION" \
    KC_PROV_MACOS_BUILD="$KC_PROV_MACOS_BUILD" \
    KC_PROV_XCODE_VERSION="$KC_PROV_XCODE_VERSION" \
    KC_PROV_XCODE_BUILD="$KC_PROV_XCODE_BUILD" \
    KC_PROV_XCODEGEN_VERSION="$KC_PROV_XCODEGEN_VERSION" \
    KC_PROV_SWIFT_VERSION="$KC_PROV_SWIFT_VERSION" \
    KC_PROV_MACOS_SDK="$KC_PROV_MACOS_SDK" \
    KC_PROV_IOS_SDK="$KC_PROV_IOS_SDK" \
    python3 - <<'PY'
import datetime
import json
import os
import plistlib

with open(os.environ["KC_PROV_INFO_PLIST"], "rb") as info_file:
    info = plistlib.load(info_file)

manifest = {
    "format": 1,
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "source": {
        "commit": os.environ["KC_PROV_SOURCE_COMMIT"],
        "tree": os.environ["KC_PROV_SOURCE_TREE"],
        "clean": True,
    },
    "toolchain": {
        "macos_version": os.environ["KC_PROV_MACOS_VERSION"],
        "macos_build": os.environ["KC_PROV_MACOS_BUILD"],
        "xcode_version": os.environ["KC_PROV_XCODE_VERSION"],
        "xcode_build": os.environ["KC_PROV_XCODE_BUILD"],
        "xcodegen_version": os.environ["KC_PROV_XCODEGEN_VERSION"],
        "swift_version": os.environ["KC_PROV_SWIFT_VERSION"],
        "sdks": {
            "macos": os.environ["KC_PROV_MACOS_SDK"],
            "iphoneos": os.environ["KC_PROV_IOS_SDK"],
        },
        "artifact": {
            "build_machine_os_build": info.get("BuildMachineOSBuild", ""),
            "xcode_build": info.get("DTXcodeBuild", ""),
            "sdk_name": info.get("DTSDKName", ""),
            "platform_version": info.get("DTPlatformVersion", ""),
        },
    },
    "build": {
        "target": os.environ["KC_PROV_TARGET"],
        "scheme": os.environ["KC_PROV_SCHEME"],
        "configuration": os.environ["KC_PROV_CONFIGURATION"],
        "platform": os.environ["KC_PROV_PLATFORM"],
        "bundle_identifier": info.get("CFBundleIdentifier", ""),
        "marketing_version": info.get("CFBundleShortVersionString", ""),
        "build_number": info.get("CFBundleVersion", ""),
    },
    "artifact": {
        "path": os.environ["KC_PROV_ARTIFACT_RELATIVE"],
        "sha256": os.environ["KC_PROV_ARTIFACT_SHA256"],
    },
    "signing": {
        "class": os.environ["KC_PROV_SIGNING_CLASS"],
        "team_id": os.environ["KC_PROV_TEAM_ID"],
        "verification": os.environ["KC_PROV_SIGNING_STATUS"],
    },
    "entitlements_summary": json.loads(os.environ["KC_PROV_ENTITLEMENTS_JSON"]),
    "notarization": {
        "status": os.environ["KC_PROV_NOTARIZATION_STATUS"],
        "submission_id": os.environ["KC_PROV_NOTARIZATION_SUBMISSION_ID"] or None,
        "stapler": os.environ["KC_PROV_STAPLER_STATUS"],
        "gatekeeper": os.environ["KC_PROV_GATEKEEPER_STATUS"],
    },
}

manifest_path = os.environ["KC_PROV_MANIFEST_PATH"]
temporary_manifest_path = manifest_path + ".tmp"
with open(temporary_manifest_path, "w", encoding="utf-8") as manifest_file:
    json.dump(manifest, manifest_file, indent=2, sort_keys=True)
    manifest_file.write("\n")
os.replace(temporary_manifest_path, manifest_path)
PY
}
