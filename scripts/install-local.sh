#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_PRODUCTS="$PROJECT_ROOT/.derivedData/Build/Products/Release"
APP_SOURCE="$BUILD_PRODUCTS/KeyCourier.app"
CLI_SOURCE="$BUILD_PRODUCTS/keycourier"
APP_DESTINATION="/Applications/KeyCourier.app"
CLI_DIRECTORY="$HOME/.local/bin"
SKILL_SOURCE="$PROJECT_ROOT/Integrations/skills/keycourier"
SKILL_DESTINATION="$HOME/.agents/skills/keycourier"
CLAUDE_SKILL_DESTINATION="$HOME/.claude/skills/keycourier"
BACKUP_ROOT="$HOME/Library/Application Support/KeyCourier/Install Backups"
APP_DATA_ROOT="$HOME/Library/Application Support/KeyCourier"
STAMP="$(date +%Y%m%d-%H%M%S)"
STAGED_APP="/Applications/.KeyCourier.install.$$"
SIGNING_TEAM="${KEYCOURIER_SIGNING_TEAM:-T27WF6673W}"

cleanup_staged_app() {
    if test -e "$STAGED_APP"; then
        rm -R "$STAGED_APP"
    fi
}

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "KeyCourier requires Xcode command-line tools." >&2
    exit 1
fi
if ! test -w /Applications; then
    echo "KeyCourier cannot write to /Applications for this user." >&2
    exit 1
fi
if ! security find-identity -v -p codesigning | grep -Eq "Apple Development: .*\\($SIGNING_TEAM\\)"; then
    echo "KeyCourier requires an Apple Development signing identity for team $SIGNING_TEAM." >&2
    exit 1
fi

if command -v xcodegen >/dev/null 2>&1; then
    (cd "$PROJECT_ROOT" && xcodegen generate >/dev/null)
fi

xcodebuild \
    -project "$PROJECT_ROOT/KeyCourier.xcodeproj" \
    -scheme KeyCourier \
    -configuration Release \
    -derivedDataPath "$PROJECT_ROOT/.derivedData" \
    -jobs 2 \
    -allowProvisioningUpdates \
    -allowProvisioningDeviceRegistration \
    build >/tmp/keycourier-release-build.log

test -d "$APP_SOURCE"
test -x "$CLI_SOURCE"
codesign --force --sign - "$CLI_SOURCE"
mkdir -p "$BACKUP_ROOT" "$CLI_DIRECTORY" "$(dirname "$SKILL_DESTINATION")" "$(dirname "$CLAUDE_SKILL_DESTINATION")"
chmod 700 "$APP_DATA_ROOT" "$BACKUP_ROOT" "$CLI_DIRECTORY" "$(dirname "$SKILL_DESTINATION")" "$(dirname "$CLAUDE_SKILL_DESTINATION")"

if test -e "$STAGED_APP"; then
    echo "Unexpected staging path already exists: $STAGED_APP" >&2
    exit 1
fi
trap cleanup_staged_app EXIT
ditto "$APP_SOURCE" "$STAGED_APP"
codesign --verify --deep --strict "$STAGED_APP"

if test -e "$APP_DESTINATION"; then
    osascript -e 'tell application id "com.drewsdigest.KeyCourier" to quit' >/dev/null 2>&1 || true
    mv "$APP_DESTINATION" "$BACKUP_ROOT/KeyCourier-$STAMP.app"
fi
mv "$STAGED_APP" "$APP_DESTINATION"
trap - EXIT
install -m 755 "$CLI_SOURCE" "$CLI_DIRECTORY/keycourier"

if test -e "$SKILL_DESTINATION" || test -L "$SKILL_DESTINATION"; then
    mv "$SKILL_DESTINATION" "$BACKUP_ROOT/keycourier-agents-skill-$STAMP"
fi
ditto "$SKILL_SOURCE" "$SKILL_DESTINATION"

if test -e "$CLAUDE_SKILL_DESTINATION" || test -L "$CLAUDE_SKILL_DESTINATION"; then
    mv "$CLAUDE_SKILL_DESTINATION" "$BACKUP_ROOT/keycourier-claude-skill-$STAMP"
fi
ln -s "$SKILL_DESTINATION" "$CLAUDE_SKILL_DESTINATION"

open "$APP_DESTINATION"
echo "Installed KeyCourier.app, keycourier CLI and agent skill."
