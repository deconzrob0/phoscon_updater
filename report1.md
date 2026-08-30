# Phoscon Firmware Updater — Code Audit

**File:** `updater.html` (37 KB, 1350 lines)
**Version:** v0.7.2
**Audited:** 2026-08-30

---

## 1. Security Issues

### 1.1 No Content-Security-Policy or Subresource Integrity

The page loads no external scripts or styles (fully self-contained), but it does make two `fetch()` calls at runtime:

- `https://phoscon.de/downloads/phoscon_firmware.json` (firmware version manifest)
- `https://deconz.dresden-elektronik.de/...` (firmware `.GCF` download, user-selected)

**Risk:** If the file is opened via `file://` and the network is compromised (MITM, DNS spoofing), a tampered JSON could inject malicious firmware URLs. Since the file is intended for offline use, this is low-risk in practice, but there is no integrity verification (no hash check, no signature) on the downloaded firmware before it is flashed.

**Recommendation:** Consider adding a SHA-256 hash of the firmware file to the JSON manifest and verifying it client-side before flashing. At minimum, document that the user should verify the firmware download against the checksum published on the dresden-elektronik site.

### 1.2 No `X-Content-Type-Options` equivalent for file opens

Not applicable to a local HTML file, but if ever served from a web server, MIME sniffing could be a concern. Low priority.

---

## 2. Bugs

### 2.1 ReferenceError: `err` is not defined (line 673)

```javascript
} catch (e) {
    console.log("failed to obtain firmware from server.");
    console.error(err)   // <-- BUG: `err` is not defined; should be `e`
}
```

The catch block references `err` instead of the caught exception `e`. This will throw a `ReferenceError` whenever the firmware download fails, masking the original error and potentially crashing the route handler.

**Impact:** User sees a confusing secondary error in the console; the actual download failure reason is lost. The UI shows no error message (the `TODO show error` comment confirms this is incomplete).

**Fix:** Change `console.error(err)` → `console.error(e)`.

---

### 2.2 `closePort()` may crash if `portReader` is null (line 1280)

```javascript
function closePort(app) {
    if (app.port) {
        keepReading = false;
        portReader.cancel();  // <-- portReader may be null
    }
}
```

`portReader` is a module-level `let` initialized to `undefined`. If `closePort()` is called before `readUntilClosed()` has started (e.g., the user navigates away quickly, or `updateFirmwareV3` throws before the reader loop begins), `portReader.cancel()` throws a `TypeError`.

**Impact:** Uncaught exception in the `updatefailed` / `updatedone` routes. The port may not be properly released.

**Fix:** Guard with `if (portReader) portReader.cancel();` or check `app.port.readable` first.

---

### 2.3 `readUntilClosed()` — reader lock release race (lines 1086–1109)

```javascript
async function readUntilClosed(app) {
    const port = app.port;
    while (port.readable && keepReading) {
        portReader = port.readable.getReader();
        try {
            while (true) {
                const { value, done } = await portReader.read();
                if (done) break;
                onReceivedData(app, value);
            }
        } catch (err) {
            console.log(err);
        } finally {
            portReader.releaseLock();
        }
    }
    // port.close() is commented out
}
```

- The `while (port.readable && keepReading)` loop can re-acquire the reader if the inner loop exits early (e.g., an error in `onReceivedData`). This is likely unintended — the reader should be acquired once.
- `port.close()` is commented out (line 1107–1108), so the port is only closed in the `.then()` callback of `readUntilClosed()` inside `updateFirmwareV3`. If `readUntilClosed()` never resolves (e.g., `keepReading` stays true and the read loop hangs), the port is never closed.
- If `closePort()` sets `keepReading = false` and calls `portReader.cancel()`, the inner loop's `read()` will resolve with `done: true`, the `finally` block releases the lock, and the outer `while` re-checks `keepReading` (now false) and exits. This path works, but only if `portReader` is non-null (see bug 2.2).

**Impact:** Potential port leak in edge cases; the device may remain locked until the browser tab is closed.

---

### 2.4 `v3UpdateDataReq()` — `pkg.buffer` may be a subarray (line 1149)

```javascript
let dv = new DataView(pkg.buffer);
let offset = dv.getUint32(2, true);
```

`pkg` is the result of `rx.buf.subarray(0, rx.bufpos - 2)` (line 482). `subarray()` returns a view sharing the same `ArrayBuffer`. `pkg.buffer` is the **full** 2048-byte buffer, not the subarray's logical bounds. `new DataView(pkg.buffer)` creates a view over the entire 2048-byte buffer.

The reads at offsets 2 and 6 happen to be within the valid packet range (the packet is at least 8 bytes), so this works in practice. However, it is fragile: if the packet were shorter, or if the subarray started at a non-zero offset in the buffer, the reads would be wrong.

**Impact:** Currently functional but fragile. A future change to packet framing could silently corrupt the offset/length reads.

**Fix:** Use `new DataView(pkg.buffer, pkg.byteOffset, pkg.byteLength)` to respect the subarray's actual bounds.

---

### 2.5 `v3VerifyAppCRC32()` — same subarray issue (line 1128)

```javascript
let dv = new DataView(pkg.buffer);
let btlVersion = dv.getUint32(2, true);
let crc32 = dv.getUint32(6, true);
```

Same issue as 2.4 — `pkg.buffer` is the full 2048-byte buffer.

**Fix:** Same as 2.4.

---

### 2.6 `routes.start` — `location.reload(true)` is deprecated (line 558)

```javascript
location.reload(true); // force full reload to start fresh
```

The boolean argument to `location.reload()` is non-standard and deprecated. In modern browsers it is ignored. The call itself still works (it reloads the page), but the `true` flag is a no-op.

**Impact:** Cosmetic — no functional issue, but misleading.

**Fix:** Use `location.reload()` without arguments, or `window.location.replace(location.href)`.

---

### 2.7 `routes.firmwareselect` — async function returns a Promise but route handler doesn't await it

```javascript
routes.firmwareselect = async function routeFirmwareSelect() {
    // ...
    getServerFirmwareVersions()
    .then(() => { /* render firmware buttons */ })
    .catch((e) => { /* log error */ });
    // ...
};
```

The route function is `async` but the `fetch` is fire-and-forget. The view template is rendered immediately, and the firmware buttons appear later when the fetch resolves. If the fetch fails (offline use), the user sees only the "Local file" button with no error message.

**Impact:** In offline mode (the stated use case), the firmware version buttons silently fail to appear. The user can still use "Local file" but gets no feedback that the online lookup failed.

**Fix:** Show a subtle error notice (e.g., "Online firmware list unavailable — use Local file") when the fetch fails.

---

### 2.8 `routes.firmwareselect` — `app.gcfFile` is reset after the async fetch setup (lines 688–690)

```javascript
getServerFirmwareVersions()
.then(() => {
    // ... sets app.gcfFile on button click ...
})
.catch(...);

// These run synchronously, BEFORE the fetch resolves:
app.gcfFile = null;
app.gcfFileDataView = null;
app.gcfHeader = null;
```

The `app.gcfFile = null` lines execute immediately after setting up the event listener, before any button click. This is harmless because the button click handler sets `app.gcfFile` fresh, but it's misleading — it looks like it's clearing state that was just set, but it's actually clearing the initial `null` values.

**Impact:** No functional bug, but confusing code. The comments suggest these are meant to reset state between navigations, but they run at the wrong time.

---

### 2.9 `gcfParseFile()` — no bounds checking on DataView reads (lines 948–1005)

```javascript
const magic = dv.getUint32(pos, true);  // pos = 0
pos += 4;
if (magic == 0xcafefeed) {
    res.fileType = dv.getUint8(pos);    // pos = 4
    // ... continues reading up to ~40 bytes ...
}
```

If the user selects a file smaller than the expected header size (e.g., a truncated or corrupt `.GCF` file), `dv.getUint32()` / `dv.getUint8()` will throw a `RangeError` (index out of bounds). This is not caught — the `FileReader.onload` handler (line 702) has no try/catch around `gcfParseFile()`.

**Impact:** Selecting a too-small file crashes the file-input handler with an uncaught exception. The user sees nothing — the UI stays on the firmware select screen.

**Fix:** Wrap `gcfParseFile()` in a try/catch, or add a minimum-size check before parsing (`if (dv.byteLength < 14) return {valid: false}`).

---

### 2.10 `gcfParseFile()` — `res.magic1` is set but never used (line 967)

```javascript
res.magic1 = dv.getUint32(pos, true);
```

The product-specific magic (0xDEC0DE02 for Hive, 0xDEC0DE03 for ConBee III) is read into `res.magic1` but never validated or used downstream. The code reads it, advances `pos`, and moves on.

**Impact:** A firmware file with the wrong product magic (e.g., a Hive firmware file selected for a ConBee III) would pass validation and be flashed, potentially bricking the device.

**Fix:** Validate `res.magic1` against the expected value for the selected product, or at least log a warning on mismatch.

---

### 2.11 `onPacket()` — `COM_STATE_VX_WAIT_TIMER` branch is empty (line 1020)

```javascript
if (app.state === COM_STATE_VX_WAIT_TIMER) {
    // empty — no handling
} else if (pkg[0] == BTL_MAGIC) {
    // ...
}
```

When in the `COM_STATE_VX_WAIT_TIMER` state (after sending the UART reset command), any incoming packet is silently ignored (falls through to the empty branch). This is by design during the 50 ms reset window, but it means that if the device sends an unexpected response during this window, it is discarded with no log.

**Impact:** Debugging difficulty. If the reset sequence fails, there's no trace of what the device actually sent.

**Fix:** Add a `console.log` in the empty branch (gated on `app.dbg`).

---

### 2.12 `v3UpdateDataReq()` — `app.outpkg` is allocated once but never resized (line 1159)

```javascript
app.outpkg = app.outpkg || new ArrayBuffer(512);
```

The output buffer is 512 bytes. The maximum data payload per request is 256 bytes (enforced at line 1172), plus 8 bytes of header = 264 bytes. This fits in 512, so it's safe. However, the buffer is never freed or reset between updates. If a second update is attempted (e.g., user goes back and retries), the stale buffer is reused.

**Impact:** No functional bug currently, but the buffer could grow if the protocol changes to allow larger payloads.

---

### 2.13 `updateFirmwareV3()` — baud rate is hardcoded (line 1287)

```javascript
await port.open({baudRate: 115200});
```

The baud rate is hardcoded to 115200, ignoring the `baudrate` value stored in `sessionStorage` (set to 115200 for both ConBee III and FLS-M in their respective routes). This is consistent today, but if a future product requires a different baud rate, this line would need to be updated.

**Impact:** Maintainability concern only. No current bug.

**Fix:** Use `parseInt(sessionStorage.getItem('baudrate'))` instead of the literal.

---

### 2.14 `protReceiveFlagged()` — `rx.buf` is never reallocated (line 516)

```javascript
if (rx.bufpos < rx.buf.length) {
    rx.buf[rx.bufpos++] = c;
    rx.crc += c;
}
```

The receive buffer is a fixed 2048-byte `Uint8Array` (allocated in `updateFirmwareV3`). If a packet exceeds 2048 bytes (minus the 2-byte CRC), the excess bytes are silently dropped (the `if` guard prevents overflow, but data is lost). The maximum firmware data request is 256 bytes + 8 header = 264, so this is safe in practice.

**Impact:** No current bug. The guard prevents memory corruption but silently truncates oversized packets.

---

### 2.15 `routes.deviceselect` — `app.deviceFilters` check is weak (line 730)

```javascript
if (!productName || !app.deviceFilters || uartReset === null) {
    navigateTo('#start');
    return;
}
```

`app.deviceFilters` is an array. If it's an empty array `[]`, the check passes (empty array is truthy). The `navigator.serial.requestPort({filters: []})` call would then show all serial ports, not just the filtered device.

**Impact:** Low — the routes always set a non-empty filter. But a future code path that clears the filter would silently degrade to "show all ports."

---

### 2.16 `routes.waitunplugged` — timer is not cleaned up on navigation (lines 827–834)

```javascript
let timerId = setInterval(() => {
    duration -= 1;
    durText.textContent = duration;
    if (duration === 0) {
        clearInterval(timerId);
        navigateTo('#waitreconnect');
    }
}, 1000);
```

If the user navigates away (e.g., clicks the browser back button) before the 10-second countdown finishes, the `setInterval` continues running. It will call `navigateTo('#waitreconnect')` even though the user has navigated elsewhere.

**Impact:** Unexpected navigation. The user is forcibly redirected to the "wait reconnect" screen even after they've gone back.

**Fix:** Store `timerId` on `app` and clear it in a `hashchange` handler or at the start of each route.

---

### 2.17 `routes.waitreconnect` — `connect` event listener is not removed on navigation (lines 850–856)

```javascript
const conn = (event) {
    app.port = event.target;
    navigator.serial.removeEventListener("connect", conn);
    navigateTo('#updating');
};
navigator.serial.addEventListener("connect", conn);
```

If the user navigates away before re-plugging the device, the `connect` listener remains registered. If they later plug in the device (e.g., for a different purpose), the handler fires and navigates to `#updating` unexpectedly.

**Impact:** Unexpected navigation on device re-plug.

**Fix:** Remove the listener when leaving the route (e.g., in a `hashchange` handler).

---

### 2.18 `routes.firmwareselect` — `#fileInput` change listener is re-attached on every visit (line 694)

```javascript
app.div.querySelector('#fileInput').addEventListener('change', (event) => {
    // ...
});
```

Every time the user navigates to `#firmwareselect`, a new `change` listener is attached to the freshly-cloned `#fileInput` element. Since `loadViewTemplate()` clears `app.div` and re-clones the template, the old element is discarded and the new one gets a fresh listener. This is actually correct — no leak. However, the `getServerFirmwareVersions()` fetch is re-triggered on every visit, even if the data is already cached in `app.firmwareVersions`.

**Impact:** Unnecessary network request on re-navigation. Minor.

**Fix:** Cache the firmware versions and skip the fetch if `app.firmwareVersions` is already populated.

---

### 2.19 `navigateTo()` — full page reload on hash change (line 526)

```javascript
function navigateTo(url) {
    window.location.href = url;
}
```

Setting `window.location.href` to a hash-only URL triggers a `hashchange` event without a full page reload. This is fine. However, `routes.start` calls `location.reload(true)` (line 558) which **does** force a full reload. This is the only place where a full reload occurs, and it's intentional (to clear state).

**Impact:** No bug. Just noting the distinction.

---

## 3. Code Quality / Maintainability

### 3.1 Commented-out code

Several blocks of commented-out code remain:

- Lines 239–241: commented-out firmware version buttons
- Line 353: commented-out state constant
- Lines 484–485: commented-out CRC error log
- Lines 754–759: commented-out device filters
- Lines 1076–1081: commented-out debug log
- Lines 1107–1108: commented-out `port.close()`
- Lines 1212–1218: commented-out debug protocol queries
- Lines 1312–1318: commented-out V1 protocol code

**Recommendation:** Remove or move to a separate debug build. Commented-out code accumulates and obscures intent.

---

### 3.2 Inconsistent naming

- `progessbar` / `progess` (lines 303–305) — misspelling of "progress"
- `Frequentry` (line 140) — misspelling of "Frequently"
- `depenencies` (line 203) — misspelling of "dependencies"
- `trouble shoot` (line 324) — should be "troubleshoot"
- `uart_reset` is stored as a string in sessionStorage but compared with `parseInt()` in some places and `=== null` in others

**Recommendation:** Fix typos in user-facing text. Standardize sessionStorage value handling.

---

### 3.3 `app` object is a global mutable singleton

The `app` object holds all state: current route, device filters, port, firmware data, RX buffer, timers, etc. There's no encapsulation — any function can mutate any field. This makes the code hard to reason about and test.

**Recommendation:** For a single-file tool this is acceptable, but if the code grows, consider a more structured state management approach.

---

### 3.4 No input validation on firmware file size

`gcfParseFile()` validates the header structure but does not check that the file size is reasonable for the target device (e.g., ConBee III firmware is ~198 KB). A user could select a 1 MB file with a valid header and attempt to flash it.

**Recommendation:** Add a sanity check on file size (e.g., reject files > 1 MB).

---

### 3.5 `onSideLoad` is a typo for `onLoad` (line 1341)

```javascript
window.addEventListener("load", onSideLoad);
```

`onSideLoad` is presumably a typo for `onLoad` or `onInitialLoad`.

---

### 3.6 `router()` — unused `popstate` listener (lines 1337–1339)

```javascript
window.addEventListener("popstate", (event) => {
  
});
```

Empty handler. Either implement it or remove it.

---

### 3.7 `routes` object is declared empty and populated later (lines 370–372)

```javascript
const routes = {
};
```

Then routes are added via `routes.start = ...`, etc. This works but is unusual. A single object literal would be cleaner.

---

## 4. UX Issues

### 4.1 No error feedback to the user

Multiple `TODO show error` comments (lines 668, 697, 712) indicate that error states are not surfaced to the user. When a firmware download fails, a file is invalid, or the flash fails, the user sees a generic "Error" page with no details.

**Recommendation:** Display the specific error message (at minimum, the console error text) on the error page.

---

### 4.2 No progress indication during firmware download

When the user clicks a firmware version button, the file is downloaded silently. There's no progress bar, spinner, or "downloading..." indicator. On a slow connection, the user may think the button is unresponsive.

**Recommendation:** Show a download progress indicator (using `fetch` with a `ReadableStream` reader for byte-level progress, or at least a "downloading..." status).

---

### 4.3 No confirmation before flashing

The user goes from "Select firmware" → "Connect device" → "Flashing" with no explicit confirmation step. If the user selects the wrong firmware or the wrong device, the flash proceeds immediately.

**Recommendation:** Add a confirmation dialog: "Flash [firmware version] to [device name]? This may take X minutes. Confirm?"

---

### 4.4 No way to abort a flash in progress

Once the flash starts, there's no "Cancel" button. If the user realizes they've selected the wrong firmware, they have to close the browser tab (which may leave the device in an inconsistent state).

**Recommendation:** Add a "Cancel" button that closes the port and returns to the firmware select screen. (Note: aborting mid-flash may corrupt the device's firmware — this should be clearly warned.)

---

### 4.5 Browser support check is minimal (line 563)

```javascript
if ("serial" in navigator) {
    navigateTo('#productselect');
} else {
    navigateTo('#unsupportedbrowser');
}
```

This checks for the Web Serial API, which is correct. However, the Web Serial API requires a **secure context** (HTTPS or `localhost` or `file://`). When opened via `file://`, the API is available in Chrome/Edge, but if the file is served over HTTP (not HTTPS), the API will be unavailable and the user will see "Browser unsupported" with no explanation.

**Recommendation:** In the unsupported browser message, mention that the page must be opened via `file://` or HTTPS.

---

### 4.6 No indication of which firmware version is currently installed on the device

The updater doesn't query the device's current firmware version before flashing. The user has no way to know if the selected firmware is an upgrade, downgrade, or the same version.

**Recommendation:** After connecting, query the bootloader for the current firmware version (if the protocol supports it) and display it.

---

## 5. Protocol / Firmware-Specific Concerns

### 5.1 No firmware signature verification

The GCF file format includes a CRC32 (for fileType 60/90) but no cryptographic signature. The updater verifies the CRC32 of the image against the GCF header, but this is an integrity check, not an authenticity check. A malicious actor who can modify the firmware file (or the download) can flash arbitrary code to the device.

**Recommendation:** This is a limitation of the GCF format, not the updater. However, the updater could add an optional signature verification step (e.g., check a SHA-256 hash against a known-good value).

---

### 5.2 ConBee II is not supported in the web updater

The FAQ and wiki both note that ConBee II support is "coming soon." The device filters for ConBee II (VID 0x1cf1, PID 0x0030) are commented out (lines 756–758). The GCF parser also explicitly rejects ConBee II firmware (fileType not 60 or 90 → `res.valid = false`, line 999).

**Impact:** ConBee II users must use GCFFlasher. This is a known limitation, not a bug.

---

### 5.3 No support for ConBee I or RaspBee

The web updater only supports ConBee III and FLS-M. ConBee I, RaspBee I, and RaspBee II require GCFFlasher. This is by design (the Web Serial API + bootloader protocol combination is only implemented for CB3 and FLS-M).

---

## 6. Summary Table

| # | Severity | Category | Description | Line(s) |
|---|----------|----------|-------------|---------|
| 1.1 | Low | Security | No firmware integrity verification (no hash/signature check) | 544, 653 |
| 2.1 | **High** | Bug | `ReferenceError: err is not defined` — masks download errors | 673 |
| 2.2 | **High** | Bug | `closePort()` crashes if `portReader` is null | 1280 |
| 2.3 | Medium | Bug | `readUntilClosed()` reader lock race / port leak | 1086–1109 |
| 2.4 | Medium | Bug | `DataView(pkg.buffer)` ignores subarray offset in `v3UpdateDataReq` | 1149 |
| 2.5 | Medium | Bug | Same subarray issue in `v3VerifyAppCRC32` | 1128 |
| 2.6 | Low | Bug | `location.reload(true)` deprecated | 558 |
| 2.7 | Medium | Bug | Offline firmware fetch fails silently — no user feedback | 628–685 |
| 2.8 | Low | Quality | `app.gcfFile = null` reset runs at wrong time (harmless) | 688–690 |
| 2.9 | **High** | Bug | `gcfParseFile()` throws `RangeError` on small files — uncaught | 948–1005 |
| 2.10 | **High** | Bug | `res.magic1` (product ID) read but never validated | 967 |
| 2.11 | Low | Quality | Empty `COM_STATE_VX_WAIT_TIMER` branch — no debug log | 1020 |
| 2.12 | Low | Quality | `app.outpkg` never freed/reset between updates | 1159 |
| 2.13 | Low | Quality | Baud rate hardcoded, ignoring `sessionStorage` | 1287 |
| 2.14 | Low | Quality | RX buffer overflow silently drops bytes (safe today) | 516 |
| 2.15 | Low | Bug | Empty `deviceFilters` array passes truthy check | 730 |
| 2.16 | Medium | Bug | `setInterval` timer not cleaned up on navigation | 827–834 |
| 2.17 | Medium | Bug | `connect` event listener not removed on navigation | 850–856 |
| 2.18 | Low | Quality | Firmware version fetch re-triggered on every visit | 628 |
| 2.19 | Info | Quality | `navigateTo()` vs `location.reload()` distinction | 526, 558 |
| 4.1 | Medium | UX | No error feedback to user (multiple `TODO show error`) | 668, 697, 712 |
| 4.2 | Medium | UX | No download progress indicator | 650–675 |
| 4.3 | Medium | UX | No confirmation before flashing | — |
| 4.4 | Medium | UX | No way to abort a flash in progress | — |
| 4.5 | Low | UX | "Browser unsupported" message doesn't explain secure context requirement | 563–567 |
| 4.6 | Low | UX | No indication of current firmware version on device | — |
| 5.1 | Medium | Security | No firmware signature verification (GCF format limitation) | — |

**High-severity items (should fix before use):** 2.1, 2.2, 2.9, 2.10

---

## 7. Recommendations (Priority Order)

1. **Fix `ReferenceError` (2.1):** `console.error(err)` → `console.error(e)`. One-word fix, eliminates a crash.
2. **Guard `closePort()` (2.2):** Add null check for `portReader`.
3. **Bounds-check `gcfParseFile()` (2.9):** Reject files < 14 bytes before parsing. Wrap in try/catch.
4. **Validate product magic (2.10):** Check `res.magic1` against expected value for the selected product.
5. **Clean up timers/listeners on navigation (2.16, 2.17):** Store references on `app`, clear in `hashchange`.
6. **Use subarray-aware DataView (2.4, 2.5):** `new DataView(pkg.buffer, pkg.byteOffset, pkg.byteLength)`.
7. **Add user-facing error messages (4.1):** Surface the `console.error` text on the error page.
8. **Add download progress (4.2) and flash confirmation (4.3):** Improve UX for a destructive operation.
9. **Remove commented-out code (3.1):** Clean up the file.
10. **Fix typos (3.2):** `progessbar` → `progressbar`, `Frequentry` → `Frequently`, etc.
