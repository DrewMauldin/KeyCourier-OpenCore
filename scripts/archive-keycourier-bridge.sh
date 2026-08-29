#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_ROOT="${KEYCOURIER_ARTIFACT_DIR:-$PROJECT_ROOT/.releaseArtifacts/bridge/$BUILD_STAMP}"
ARCHIVE_PATH="$ARTIFACT_ROOT/KeyCourierBridge.xcarchive"
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
provenance_capture_build_context "KeyCourierBridge" "KeyCourierBridge" "Release" "macOS"
security find-identity -v -p codesigning 2>/dev/null | grep -q 'Developer ID Application:' || {
    echo "A Developer ID Application certificate is required in this login Keychain." >&2; exit 1;
}
if [[ "$NOTARIZE" == true && -z "${KEYCOURIER_NOTARY_PROFILE:-}" ]]; then
    echo "Set KEYCOURIER_NOTARY_PROFILE to an existing notarytool Keychain profile." >&2
    exit 1
fi

mkdir -p "$ARTIFACT_ROOT"
[[ ! -e "$ARCHIVE_PATH" && ! -e "$EXPORT_PATH" ]] || {
    echo "Refusing to overwrite release evidence in $ARTIFACT_ROOT." >&2; exit 1;
}
cd "$PROJECT_ROOT"
xcodebuild -project KeyCourier.xcodeproj -scheme KeyCourierBridge -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$ARCHIVE_PATH" archive
xcodebuild -exportArchive -allowProvisioningUpdates \
    -archivePath "$ARCHIVE_PATH" -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist "$PROJECT_ROOT/config/release/ExportOptions-DeveloperID.plist"

APP_PATH="$EXPORT_PATH/keycourier-bridge.app"
[[ -d "$APP_PATH" ]] || { echo "Export did not produce keycourier-bridge.app." >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
DETAILS="$(codesign -dvv "$APP_PATH" 2>&1)"
grep -q 'Authority=Developer ID Application:' <<<"$DETAILS" || {
    echo "The Bridge is not signed with Developer ID Application." >&2; exit 1;
}
grep -q 'TeamIdentifier=T27WF6673W' <<<"$DETAILS" || {
    echo "The Bridge is signed by the wrong team." >&2; exit 1;
}
grep -q 'flags=.*runtime' <<<"$DETAILS" || {
    echo "The Bridge is missing hardened runtime." >&2; exit 1;
}
codesign -d --entitlements :- "$APP_PATH" >"$ARTIFACT_ROOT/entitlements.plist" 2>/dev/null
plutil -lint "$ARTIFACT_ROOT/entitlements.plist" >/dev/null
[[ "$(plutil -extract 'com\.apple\.security\.application-groups.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "T27WF6673W.com.drewsdigest.KeyCourier.bridge" ]] || {
    echo "The Bridge is missing its App Group." >&2; exit 1;
}
if plutil -extract 'keychain-access-groups' raw "$ARTIFACT_ROOT/entitlements.plist" >/dev/null 2>&1; then
    echo "The Bridge must not have a vault Keychain access group." >&2; exit 1
fi

ZIP_PATH="$ARTIFACT_ROOT/KeyCourierBridge.zip"
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
        echo "The Bridge was not accepted by notarisation." >&2
        exit 1
    }
    xcrun stapler staple "$APP_PATH"
    STAPLER_STATUS="passed"
    xcrun stapler validate "$APP_PATH"
    spctl --assess --type execute --verbose=2 "$APP_PATH"
    GATEKEEPER_STATUS="accepted"
    ditto -c -k --keepParent "$APP_PATH" "$ARTIFACT_ROOT/KeyCourierBridge-notarized.zip"
    ZIP_PATH="$ARTIFACT_ROOT/KeyCourierBridge-notarized.zip"
fi
(cd "$ARTIFACT_ROOT" && shasum -a 256 "$(basename "$ZIP_PATH")") >"$ARTIFACT_ROOT/SHA256SUMS"
provenance_verify_source_unchanged "$PROJECT_ROOT"
provenance_write_manifest \
    "$ARTIFACT_ROOT" \
    "$ZIP_PATH" \
    "KeyCourierBridge" \
    "KeyCourierBridge" \
    "Release" \
    "macOS" \
    "$APP_PATH/Contents/Info.plist" \
    "Developer ID Application" \
    "T27WF6673W" \
    "verified" \
    "app-group,hardened-runtime,keychain-vault=false,sandbox=false" \
    "$NOTARIZATION_STATUS" \
    "$NOTARIZATION_SUBMISSION_ID" \
    "$STAPLER_STATUS" \
    "$GATEKEEPER_STATUS"
echo "Bridge artifact: $ZIP_PATH"
[[ "$NOTARIZE" == true ]] || echo "No notarisation was performed."
