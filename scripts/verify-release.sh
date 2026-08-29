#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DERIVED_DATA="$PROJECT_ROOT/.derivedData"

command -v xcodegen >/dev/null
command -v xcodebuild >/dev/null

cd "$PROJECT_ROOT"

assert_privacy_manifest() {
    local manifest="$1"
    if [[ ! -f "$manifest" ]]; then
        echo "Missing packaged privacy manifest: $manifest" >&2
        return 1
    fi

    plutil -lint "$manifest" >/dev/null
    python3 - "$manifest" <<'PY'
import plistlib
import sys

manifest_path = sys.argv[1]
with open(manifest_path, "rb") as manifest_file:
    manifest = plistlib.load(manifest_file)

for entry in manifest.get("NSPrivacyAccessedAPITypes", []):
    if not isinstance(entry, dict):
        continue
    if entry.get("NSPrivacyAccessedAPIType") != "NSPrivacyAccessedAPICategoryUserDefaults":
        continue
    reasons = entry.get("NSPrivacyAccessedAPITypeReasons", [])
    if isinstance(reasons, list) and "CA92.1" in reasons:
        break
else:
    raise SystemExit(
        f"{manifest_path} must declare UserDefaults reason CA92.1"
    )
PY
}

xcodegen generate >/dev/null
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourierCore \
    -configuration Debug \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build-for-testing
DYLD_LIBRARY_PATH="$DERIVED_DATA/Build/Products/Debug" \
    xcrun xctest "$DERIVED_DATA/Build/Products/Debug/KeyCourierCoreTests.xctest"
(cd HostAgent && python3 -m unittest discover -s tests -p 'test_*.py')
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourier \
    -configuration Release \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourierStore \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourierBridge \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build
xcodebuild \
    -project KeyCourier.xcodeproj \
    -scheme KeyCourierMobile \
    -configuration Release \
    -sdk iphonesimulator \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build
assert_privacy_manifest \
    "$DERIVED_DATA/Build/Products/Release/KeyCourier.app/Contents/Resources/PrivacyInfo.xcprivacy"
assert_privacy_manifest \
    "$DERIVED_DATA/Build/Products/Release-iphonesimulator/KeyCourier.app/PrivacyInfo.xcprivacy"
git diff --check
