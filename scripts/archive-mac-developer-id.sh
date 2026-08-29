#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_ROOT="${KEYCOURIER_ARTIFACT_DIR:-$PROJECT_ROOT/.releaseArtifacts/mac/$BUILD_STAMP}"
ARCHIVE_PATH="$ARTIFACT_ROOT/KeyCourier.xcarchive"
EXPORT_PATH="$ARTIFACT_ROOT/export"
NOTARIZE=false

# shellcheck source=release-provenance.sh
source "$SCRIPT_DIR/release-provenance.sh"

if [[ "${1:-}" == "--notarize" ]]; then
    NOTARIZE=true
elif [[ $# -ne 0 ]]; then
    echo "Usage: $0 [--notarize]" >&2
    exit 64
fi

command -v xcodebuild >/dev/null || { echo "Install Xcode command-line tools first." >&2; exit 1; }
provenance_capture_source "$PROJECT_ROOT"
provenance_capture_build_context "KeyCourier" "KeyCourier" "Release" "macOS"
if ! security find-identity -v -p codesigning 2>/dev/null | grep -q 'Developer ID Application:'; then
    echo "A Developer ID Application certificate is required in this login Keychain." >&2
    exit 1
fi
if [[ "$NOTARIZE" == true && -z "${KEYCOURIER_NOTARY_PROFILE:-}" ]]; then
    echo "Set KEYCOURIER_NOTARY_PROFILE to an existing notarytool Keychain profile." >&2
    exit 1
fi

mkdir -p "$ARTIFACT_ROOT"
if [[ -e "$ARCHIVE_PATH" || -e "$EXPORT_PATH" ]]; then
    echo "Refusing to overwrite existing release evidence in $ARTIFACT_ROOT." >&2
    exit 1
fi
cd "$PROJECT_ROOT"
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourier \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -archivePath "$ARCHIVE_PATH" \
    archive
xcodebuild -exportArchive \
    -allowProvisioningUpdates \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist "$PROJECT_ROOT/config/release/ExportOptions-DeveloperID.plist"

APP_PATH="$EXPORT_PATH/KeyCourier.app"
[[ -d "$APP_PATH" ]] || { echo "Export did not produce KeyCourier.app." >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
SIGNING_DETAILS="$(codesign -dvv "$APP_PATH" 2>&1)"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP_PATH/Contents/Info.plist")" == "com.drewsdigest.KeyCourier" ]] || {
    echo "The exported Mac bundle identifier is not com.drewsdigest.KeyCourier." >&2
    exit 1
}
grep -q 'Authority=Developer ID Application:' <<<"$SIGNING_DETAILS" || {
    echo "The exported Mac app is not signed with Developer ID Application." >&2
    exit 1
}
grep -q 'TeamIdentifier=T27WF6673W' <<<"$SIGNING_DETAILS" || {
    echo "The exported Mac app is signed by the wrong team." >&2
    exit 1
}
grep -q 'flags=.*runtime' <<<"$SIGNING_DETAILS" || {
    echo "The exported Mac app is missing hardened runtime." >&2
    exit 1
}
CLI_PATH="$APP_PATH/Contents/Resources/Automation/keycourier"
SKILL_PATH="$APP_PATH/Contents/Resources/Automation/skill/keycourier/SKILL.md"
[[ -x "$CLI_PATH" && -f "$SKILL_PATH" ]] || {
    echo "The exported Mac app is missing its bundled CLI or agent skill." >&2
    exit 1
}
codesign --verify --strict --verbose=2 "$CLI_PATH"
CLI_SIGNING_DETAILS="$(codesign -dvv "$CLI_PATH" 2>&1)"
grep -q 'Authority=Developer ID Application:' <<<"$CLI_SIGNING_DETAILS" &&
    grep -q 'TeamIdentifier=T27WF6673W' <<<"$CLI_SIGNING_DETAILS" &&
    grep -q 'flags=.*runtime' <<<"$CLI_SIGNING_DETAILS" || {
    echo "The bundled CLI is not a hardened Developer ID build from the expected team." >&2
    exit 1
}
codesign -d --entitlements :- "$APP_PATH" \
    >"$ARTIFACT_ROOT/entitlements.plist" 2>/dev/null
plutil -lint "$ARTIFACT_ROOT/entitlements.plist" >/dev/null
[[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-environment' raw "$ARTIFACT_ROOT/entitlements.plist")" == "Production" ]] || {
    echo "The exported Mac app is missing the production CloudKit environment." >&2
    exit 1
}
[[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-identifiers.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "iCloud.com.drewsdigest.KeyCourier" ]] || {
    echo "The exported Mac app has the wrong CloudKit container." >&2
    exit 1
}
[[ "$(plutil -extract 'com\.apple\.developer\.icloud-services.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "CloudKit" ]] || {
    echo "The exported Mac app is missing the CloudKit service entitlement." >&2
    exit 1
}
plutil -extract 'com\.apple\.security\.app-sandbox' raw "$ARTIFACT_ROOT/entitlements.plist" >/dev/null 2>&1 && {
    echo "Unexpected App Sandbox entitlement in the automation edition." >&2
    exit 1
}

ZIP_PATH="$ARTIFACT_ROOT/KeyCourier.zip"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
NOTARIZATION_STATUS="not-requested"
NOTARIZATION_SUBMISSION_ID=""
STAPLER_STATUS="not-run"
GATEKEEPER_STATUS="not-run"
if [[ "$NOTARIZE" == true ]]; then
    NOTARY_JSON="$(xcrun notarytool submit "$ZIP_PATH" \
        --keychain-profile "$KEYCOURIER_NOTARY_PROFILE" \
        --wait \
        --output-format json)"
    NOTARIZATION_STATUS="$(provenance_notary_field "$NOTARY_JSON" status)"
    NOTARIZATION_SUBMISSION_ID="$(provenance_notary_field "$NOTARY_JSON" id)"
    [[ "$NOTARIZATION_STATUS" == "Accepted" ]] || {
        echo "The exported Mac app was not accepted by notarisation." >&2
        exit 1
    }
    xcrun stapler staple "$APP_PATH"
    STAPLER_STATUS="passed"
    xcrun stapler validate "$APP_PATH"
    spctl --assess --type execute --verbose=2 "$APP_PATH"
    GATEKEEPER_STATUS="accepted"
    FINAL_ZIP_PATH="$ARTIFACT_ROOT/KeyCourier-notarized.zip"
    ditto -c -k --keepParent "$APP_PATH" "$FINAL_ZIP_PATH"
    (cd "$ARTIFACT_ROOT" && shasum -a 256 "$(basename "$FINAL_ZIP_PATH")") >"$ARTIFACT_ROOT/SHA256SUMS"
else
    (cd "$ARTIFACT_ROOT" && shasum -a 256 "$(basename "$ZIP_PATH")") >"$ARTIFACT_ROOT/SHA256SUMS"
fi
provenance_verify_source_unchanged "$PROJECT_ROOT"
if [[ "$NOTARIZE" == true ]]; then
    PROVENANCE_ARTIFACT_PATH="$FINAL_ZIP_PATH"
else
    PROVENANCE_ARTIFACT_PATH="$ZIP_PATH"
fi
provenance_write_manifest \
    "$ARTIFACT_ROOT" \
    "$PROVENANCE_ARTIFACT_PATH" \
    "KeyCourier" \
    "KeyCourier" \
    "Release" \
    "macOS" \
    "$APP_PATH/Contents/Info.plist" \
    "Developer ID Application" \
    "T27WF6673W" \
    "verified" \
    "cloudkit-production,hardened-runtime,cli-hardened-runtime,keychain-group,sandbox=false" \
    "$NOTARIZATION_STATUS" \
    "$NOTARIZATION_SUBMISSION_ID" \
    "$STAPLER_STATUS" \
    "$GATEKEEPER_STATUS"

echo "Mac release artifacts: $ARTIFACT_ROOT"
if [[ "$NOTARIZE" == false ]]; then
    echo "Notarisation was not requested. Re-run with --notarize after owner approval."
fi
