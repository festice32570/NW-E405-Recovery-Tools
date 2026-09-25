# NW-E405 Recovery Research Notes

This document records the current evidence behind the recovery tool. It deliberately separates observed facts from hypotheses.

## Current Issue #1 state

The failing Japanese NW-E405 enumerates as USB `054C:01FB` and SCSI `SONY / NWWM MEM AAD2`. Standard SCSI INQUIRY works, but TEST UNIT READY and READ CAPACITY return `NOT READY / 3A00 (MEDIUM NOT PRESENT)`. Sony vendor read `FC/03` succeeds and returns `01 00 0D 00 20 02 00 00`, which the original updater treats as firmware information for the 1.x device state.

This means the USB/SCSI command processor is alive while the normal user-media path is not being exposed.

## Original Sony update package

Japanese Sony package:

- Wrapper: `NW-E40X_V2_0J.exe`
- Wrapper SHA-256: `8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7`
- Embedded package: `MSFWUPGR_NW-E40X_201J.UPG`
- UPG size: `2,131,380 bytes`
- UPG SHA-256: `82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691`
- UPG model ID: ASCII `00100000`

The official updater INI specifies `Version=2.0.01.0`, `FWInfoSize=8`, `FWConfig=20`, `ClassifyType=3`.

The official update documentation requires approximately 3 MB free on the Walkman before updating. The UPG itself is about 2.13 MB. More importantly, the original DLL explicitly handles `ERROR_DISK_FULL` from `CopyFileA` but still converges on the `FC/04` update-start block. Low free space is therefore not just a scratch-space concern; it is a plausible direct trigger for starting update from an invalid package state.

Official Sony support pages:

- https://www.sony.com/electronics/support/articles/S1Q0091
- https://www.sony.jp/support/pa_common/information/info_win7.html
- https://www.sony.jp/support/pa_common/information/info_vista.html

## What 99% means

Reverse engineering of `FWUpdater.exe` changed the recovery plan materially.

The updater calls `SendFWUpdateCommand` first. Only after that call succeeds does it enter a timed loop waiting for the Walkman to disappear/re-enumerate and report the expected new state. The progress calculation intentionally clamps to 99% while waiting. 100% is shown only after the expected device returns.

Therefore an update that reaches 99% and then times out is not evidence of a 99%-complete PC-to-device file copy. It is evidence that the updater had already accepted the package-copy/update-start stage and was waiting for device-side completion.

## SendFWUpdateCommand flow

Reverse engineered flow in `FWUpdaterCom.dll`:

1. Build `<drive>:\\MSFWUPGR.UPG`.
2. `CopyFileA` the selected official UPG to that path.
3. If `CopyFileA` fails, record an error. The DLL explicitly recognizes `ERROR_DISK_FULL (0x70)`.
4. **Both the CopyFile success path and the handled failure path converge on the same `FC/04` block.**
5. Send Sony vendor command `FC/04` as a 12-byte CDB with no data payload.
6. Return to the UI, which then waits for the Walkman to restart/reappear.

`FC/04` is therefore an update-start command, **not a PC-side firmware transport**.

For Issue #1, blindly re-sending FC/04 is unsafe. The original DLL can reach FC/04 even when CopyFile reports disk full, so the failed run may have started device-side update with a missing, stale, or incomplete package state. The exact on-device file condition is not recoverable through the current `3A00` mass-storage path.

## Windows 7 x64 assessment

The 2005 firmware updater was released for Windows 98/Me/2000/XP-era systems. Sony's later Windows 7 compatibility page does not list NW-E405/E407 and says unlisted models were not planned for Windows 7 support. The old application stack is not a supported Windows 7 environment.

However, the updater does not simply reject Windows 7. Its internal OS classifier maps NT 6.x into the same high-level backend selection path used by later NT systems. User group membership also affects backend selection; an Administrator can be routed to the direct-drive SCSI backend.

So Windows 7 x64 was an unsupported and risky environment, but it is not sufficient by itself to explain this failure. The original updater could still reach the package-copy and `FC/04` stage. The low-free-space condition remains the stronger direct failure hypothesis, with Windows 7 x64 as a possible contributing factor in re-enumeration/legacy behavior.

## UPG structure and wrong-model protection

Observed five record lengths in both official Japanese E40X and E50X packages:

- `0x50`
- `0x30`
- `0x10518`
- `0x1F8018`
- `0x04`

Their sum exactly equals `2,131,380` bytes.

The E40X model ID is `00100000`; E50X is `00110000`. The large model-dependent region differs almost completely. Therefore a force mode must never accept an E50X image merely because the updater and total size are similar.

The large payload regions have very high entropy. They may be encrypted, compressed, obfuscated, or otherwise transformed. They must not be treated as a raw flash image without further proof.

## Read-only Sony commands currently used

- `FC/03`: firmware information, allocation length 8.
- `FC/05`: GetDeviceId path for `ClassifyType=3`, allocation length 16.
- `FC/09`: GetProductInfo-shaped data-in query using the INI signature `roga`, allocation length 24.

The current main branch does not contain `FC/04`, SCSI DATA OUT, or standard SCSI write opcodes.

## Force-flash research paths

### Software path

A true software force flash requires a verified transport that can supply a known-good image/package while the normal medium reports `3A00 MEDIUM NOT PRESENT`. The original updater does not provide this; it relies on normal filesystem `CopyFileA` before `FC/04`.

No verified vendor-data-out recovery command has been found yet. Do not invent one.

### Hardware/boot-ROM path

Service documentation shows the CXR704060 family exposes `XBOOT`, `TXD1`, `RXD1`, and `DEBUG` test points. Related Sony documentation identifies XBOOT as a boot-mode selection input. This makes a ROM/service boot route plausible.

But the required logic level, timing, I/O voltage, baud rate, and boot protocol have not yet been established for NW-E405. No short-to-ground/VDD instructions should be published until those are verified.

## Release safety rule

Any future build that can write or start an update must require all of the following before a destructive operation can be enabled:

1. Persistent TXT and JSONL logging successfully opened and flushed.
2. Exact USB VID/PID and SCSI identity match.
3. Exact approved Japanese E40X firmware hash and model ID.
4. Device state classified by read-only probes.
5. Immediate pre-action revalidation.
6. Explicit expert confirmation; no automatic retry.
7. Every outgoing CDB and result journaled before/after the operation where technically possible.

Until a verified No-Media firmware transport or boot-ROM service protocol is known, the project should call itself a recovery **research/preflight** tool rather than claim guaranteed flashing.
