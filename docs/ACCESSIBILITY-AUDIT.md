# KeyCourier accessibility audit

## Findings

### P0

None found.

### P1

None found. Every action uses a native `Button`, icon-only delete controls retain meaningful labels, forms use labelled native fields and all security decisions remain keyboard-operable. The guided entry sheet focuses its labelled secure field and disables Save until a value is present.

### P2

- History status uses both a symbol and text. The decorative symbol is hidden from accessibility to avoid an unhelpful duplicate announcement.
- Long-running Keychain approval had no semantic busy feedback. The toolbar now exposes a labelled progress indicator while an operation is active.
- Entry sheets use a minimum size rather than a fixed content frame so enlarged text can reflow.
- The Home accessibility tree combines each destination's name, saved state, registration state and action without exposing raw identifiers.

## Runtime evidence

The launched debug app was inspected through the macOS accessibility tree on 26 August 2026. Home exposed Home, Requests, History and Advanced in logical order; Mac Mini and VPS each announced their saved and request-ready states; the secret sheet exposed one `secure text field`, Cancel and a disabled Save button. No secret, consumer or target IDs appeared outside Advanced.

## Manual verification

1. Enable VoiceOver and traverse the sidebar, toolbar, empty states, request card and both add forms. Expect visible labels to match spoken labels with no raw SF Symbol names.
2. Enable full keyboard access. Open and cancel each guided entry form, then approve or decline a dummy request without a pointer. Expect a predictable focus order and no trapped focus.
3. Increase the macOS text size and resize the window to its minimum. Expect controls and decision metadata to remain readable with no missing actions.
4. Enable Increase Contrast and Reduce Transparency. Expect all state to remain understandable from text and symbols, not colour alone.

Regression risk is low: these changes affect only accessibility semantics, progress feedback and adaptive sheet sizing.
