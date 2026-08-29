#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_ROOT="${KEYCOURIER_ARTIFACT_DIR:-$PROJECT_ROOT/.releaseArtifacts/store/$BUILD_STAMP}"
ARCHIVE_PATH="$ARTIFACT_ROOT/KeyCourierStore.xcarchive"
EXPORT_PATH="$ARTIFACT_ROOT/export"

# shellcheck source=release-provenance.sh
source "$SCRIPT_DIR/release-provenance.sh"

[[ $# -eq 0 ]] || { echo "Usage: $0" >&2; exit 64; }
command -v xcodebuild >/dev/null || { echo "Install Xcode command-line tools first." >&2; exit 1; }
provenance_capture_source "$PROJECT_ROOT"
provenance_capture_build_context "KeyCourierStore" "KeyCourierStore" "Release" "macOS"
security find-identity -v -p codesigning 2>/dev/null | grep -q 'Apple Distribution:' || {
    echo "An Apple Distribution certificate is required in this login Keychain." >&2
    exit 1
}

mkdir -p "$ARTIFACT_ROOT"
[[ ! -e "$ARCHIVE_PATH" && ! -e "$EXPORT_PATH" ]] || {
    echo "Refusing to overwrite release evidence in $ARTIFACT_ROOT." >&2
    exit 1
}
cd "$PROJECT_ROOT"
xcodebuild -project KeyCourier.xcodeproj -scheme KeyCourierStore -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$ARCHIVE_PATH" archive

APP_PATH="$ARCHIVE_PATH/Products/Applications/KeyCourier.app"
[[ -d "$APP_PATH" ]] || { echo "Archive did not contain KeyCourier.app." >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
DETAILS="$(codesign -dvv "$APP_PATH" 2>&1)"
grep -Eq 'Authority=(Apple Development|Apple Distribution):' <<<"$DETAILS" || {
    echo "The Store archive is not signed with an Apple team identity." >&2; exit 1;
}
grep -q 'TeamIdentifier=T27WF6673W' <<<"$DETAILS" || {
    echo "The Store app is signed by the wrong team." >&2; exit 1;
}
codesign -d --entitlements :- "$APP_PATH" >"$ARTIFACT_ROOT/entitlements.plist" 2>/dev/null
plutil -lint "$ARTIFACT_ROOT/entitlements.plist" >/dev/null
[[ "$(plutil -extract 'com\.apple\.security\.app-sandbox' raw "$ARTIFACT_ROOT/entitlements.plist")" == "true" ]] || {
    echo "The Store app is missing App Sandbox." >&2; exit 1;
}
[[ "$(plutil -extract 'com\.apple\.security\.application-groups.0' raw "$ARTIFACT_ROOT/entitlements.plist")" == "T27WF6673W.com.drewsdigest.KeyCourier.bridge" ]] || {
    echo "The Store app is missing the production Bridge App Group." >&2; exit 1;
}
[[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-environment' raw "$ARTIFACT_ROOT/entitlements.plist")" == "Production" ]] || {
    echo "The Store app is missing production CloudKit." >&2; exit 1;
}
if find "$APP_PATH/Contents" -type f \( -name keycourier -o -name keycourier-bridge \) | grep -q .; then
    echo "The Store app unexpectedly embeds an automation executable." >&2; exit 1
fi

xcodebuild -exportArchive -allowProvisioningUpdates \
    -archivePath "$ARCHIVE_PATH" -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist "$PROJECT_ROOT/config/release/ExportOptions-AppStore.plist"
PKG_PATH="$(find "$EXPORT_PATH" -maxdepth 1 -type f -name '*.pkg' -print -quit)"
[[ -n "$PKG_PATH" ]] || { echo "Export did not produce a Mac App Store package." >&2; exit 1; }
pkgutil --check-signature "$PKG_PATH" >"$ARTIFACT_ROOT/package-signature.txt"
grep -Eq 'Status: signed by a (developer|distribution) certificate issued by Apple' "$ARTIFACT_ROOT/package-signature.txt" || {
    echo "The exported package does not have an Apple installer signature." >&2; exit 1;
}
grep -Eq '3rd Party Mac Developer Installer: .*\(T27WF6673W\)' "$ARTIFACT_ROOT/package-signature.txt" || {
    echo "The exported package is signed by the wrong installer team." >&2; exit 1;
}
grep -q 'Apple Worldwide Developer Relations Certification Authority' "$ARTIFACT_ROOT/package-signature.txt" || {
    echo "The exported package is missing the Apple installer certificate chain." >&2; exit 1;
}
EXPANDED_PACKAGE="$(mktemp -d /tmp/keycourier-store-package.XXXXXX)"
trap 'rm -rf -- "$EXPANDED_PACKAGE"' EXIT
pkgutil --expand-full "$PKG_PATH" "$EXPANDED_PACKAGE/content"
FINAL_APP="$(find "$EXPANDED_PACKAGE/content" -type d -name 'KeyCourier.app' -print -quit)"
[[ -n "$FINAL_APP" ]] || { echo "The exported package does not contain KeyCourier.app." >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$FINAL_APP"
FINAL_DETAILS="$(codesign -dvv "$FINAL_APP" 2>&1)"
grep -q 'Authority=Apple Distribution:' <<<"$FINAL_DETAILS" || {
    echo "The packaged Store app is not signed with Apple Distribution." >&2; exit 1;
}
grep -q 'TeamIdentifier=T27WF6673W' <<<"$FINAL_DETAILS" || {
    echo "The packaged Store app is signed by the wrong team." >&2; exit 1;
}
[[ "$(plutil -extract CFBundleIdentifier raw "$FINAL_APP/Contents/Info.plist")" == "com.drewsdigest.KeyCourier" ]] || {
    echo "The packaged Store app has the wrong bundle identifier." >&2; exit 1;
}
codesign -d --entitlements :- "$FINAL_APP" >"$ARTIFACT_ROOT/final-entitlements.plist" 2>/dev/null
plutil -lint "$ARTIFACT_ROOT/final-entitlements.plist" >/dev/null
[[ "$(plutil -extract 'com\.apple\.security\.app-sandbox' raw "$ARTIFACT_ROOT/final-entitlements.plist")" == "true" ]] || {
    echo "The packaged Store app is missing App Sandbox." >&2; exit 1;
}
[[ "$(plutil -extract 'com\.apple\.security\.application-groups.0' raw "$ARTIFACT_ROOT/final-entitlements.plist")" == "T27WF6673W.com.drewsdigest.KeyCourier.bridge" ]] || {
    echo "The packaged Store app is missing the production Bridge App Group." >&2; exit 1;
}
[[ "$(plutil -extract 'com\.apple\.developer\.icloud-container-environment' raw "$ARTIFACT_ROOT/final-entitlements.plist")" == "Production" ]] || {
    echo "The packaged Store app is missing production CloudKit." >&2; exit 1;
}
if find "$FINAL_APP/Contents" -type f \( -name keycourier -o -name keycourier-bridge \) | grep -q .; then
    echo "The packaged Store app unexpectedly embeds an automation executable." >&2; exit 1
fi
(cd "$ARTIFACT_ROOT" && shasum -a 256 "export/$(basename "$PKG_PATH")") >"$ARTIFACT_ROOT/SHA256SUMS"
provenance_verify_source_unchanged "$PROJECT_ROOT"
provenance_write_manifest \
    "$ARTIFACT_ROOT" \
    "$PKG_PATH" \
    "KeyCourierStore" \
    "KeyCourierStore" \
    "Release" \
    "macOS" \
    "$FINAL_APP/Contents/Info.plist" \
    "Apple Distribution" \
    "T27WF6673W" \
    "verified" \
    "sandbox,network-client,app-group,cloudkit-production,keychain-group" \
    "not-applicable" \
    "" \
    "not-applicable" \
    "not-applicable"
echo "Mac App Store artifact: $PKG_PATH"
echo "No upload was performed."
