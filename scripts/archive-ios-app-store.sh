#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_ROOT="${KEYCOURIER_ARTIFACT_DIR:-$PROJECT_ROOT/.releaseArtifacts/ios/$BUILD_STAMP}"
ARCHIVE_PATH="$ARTIFACT_ROOT/KeyCourierMobile.xcarchive"
EXPORT_PATH="$ARTIFACT_ROOT/export"

# shellcheck source=release-provenance.sh
source "$SCRIPT_DIR/release-provenance.sh"

[[ $# -eq 0 ]] || { echo "Usage: $0" >&2; exit 64; }
command -v xcodebuild >/dev/null || { echo "Install Xcode command-line tools first." >&2; exit 1; }
provenance_capture_source "$PROJECT_ROOT"
provenance_capture_build_context "KeyCourierMobile" "KeyCourierMobile" "Release" "iOS"
if ! security find-identity -v -p codesigning 2>/dev/null | grep -q 'Apple Distribution:'; then
    echo "An Apple Distribution certificate is required in this login Keychain." >&2
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
    -scheme KeyCourierMobile \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE_PATH" \
    archive
xcodebuild -exportArchive \
    -allowProvisioningUpdates \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist "$PROJECT_ROOT/config/release/ExportOptions-AppStore.plist"

IPA_PATH="$(find "$EXPORT_PATH" -maxdepth 1 -name '*.ipa' -print -quit)"
[[ -n "$IPA_PATH" ]] || { echo "Export did not produce an IPA." >&2; exit 1; }
IPA_CONTENTS_PATH="$ARTIFACT_ROOT/ipa"
ditto -x -k "$IPA_PATH" "$IPA_CONTENTS_PATH"
APP_PATH="$IPA_CONTENTS_PATH/Payload/KeyCourier.app"
[[ -d "$APP_PATH" ]] || { echo "The IPA does not contain KeyCourier.app." >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
[[ -f "$APP_PATH/PrivacyInfo.xcprivacy" ]] || {
    echo "The exported app is missing PrivacyInfo.xcprivacy." >&2
    exit 1
}
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP_PATH/Info.plist")" == "com.drewsdigest.KeyCourierMobile" ]] || {
    echo "The iPhone archive has the wrong bundle identifier." >&2
    exit 1
}
SIGNING_DETAILS="$(codesign -dvv "$APP_PATH" 2>&1)"
grep -q 'Authority=Apple Distribution:' <<<"$SIGNING_DETAILS" || {
    echo "The iPhone archive is not signed with Apple Distribution." >&2
    exit 1
}
grep -q 'TeamIdentifier=T27WF6673W' <<<"$SIGNING_DETAILS" || {
    echo "The iPhone archive is signed by the wrong team." >&2
    exit 1
}
codesign -d --entitlements :- "$APP_PATH" \
    >"$ARTIFACT_ROOT/entitlements.plist" 2>/dev/null
plutil -lint "$ARTIFACT_ROOT/entitlements.plist" >/dev/null
[[ "$(plutil -extract aps-environment raw "$ARTIFACT_ROOT/entitlements.plist")" == "production" ]] &&
    [[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-environment' raw "$ARTIFACT_ROOT/entitlements.plist")" == "Production" ]] &&
    [[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-identifiers.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "iCloud.com.drewsdigest.KeyCourier" ]] &&
    [[ "$(plutil -extract 'com\.apple\.developer\.icloud-services.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "CloudKit" ]] || {
    echo "The archive does not contain production APNs/CloudKit entitlements." >&2
    exit 1
}
(cd "$ARTIFACT_ROOT" && shasum -a 256 "export/$(basename "$IPA_PATH")") >"$ARTIFACT_ROOT/SHA256SUMS"
provenance_verify_source_unchanged "$PROJECT_ROOT"
provenance_write_manifest \
    "$ARTIFACT_ROOT" \
    "$IPA_PATH" \
    "KeyCourierMobile" \
    "KeyCourierMobile" \
    "Release" \
    "iOS" \
    "$APP_PATH/Info.plist" \
    "Apple Distribution" \
    "T27WF6673W" \
    "verified" \
    "aps-production,cloudkit-production,get-task-allow=false,privacy-manifest" \
    "not-applicable" \
    "" \
    "not-applicable" \
    "not-applicable"

echo "iPhone App Store artifact: $IPA_PATH"
echo "No upload was performed. Upload only after device, CloudKit and metadata review."
