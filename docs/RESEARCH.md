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

The official update documentation requires approximately 3 MB free on the Walkman before updating. The UPG itself is 2,131,380 bytes (about 2.03 MiB). Re-auditing the original DLL with its MSVC C++ exception metadata shows that a `CopyFileA` failure is raised into the `SendFWUpdateCommand` catch handler and returns an error before `FC/04`; the earlier straight-line-control-flow interpretation was incorrect. Because Issue #1 reached the GUI's post-start 99% wait, the UPG copy likely succeeded. Low free space can still be relevant if there was enough space to store the UPG but less than Sony's ~3 MB requirement, leaving insufficient device-side work space. That remains a hypothesis, not a documented Sony root cause.

Official Sony support pages:

- https://www.sony.com/electronics/support/articles/S1Q0091
- https://www.sony.jp/support/pa_common/information/info_win7.html
- https://www.sony.jp/support/pa_common/information/info_vista.html

## What 99% means

Reverse engineering of `FWUpdater.exe` changed the recovery plan materially.

The updater calls `SendFWUpdateCommand` first. Only after that call succeeds does it enter a timed loop waiting for the Walkman to disappear/re-enumerate and report the expected new state. The progress calculation intentionally clamps to 99% while waiting. 100% is shown only after the expected device returns.

Therefore an update that reaches 99% and then times out is not evidence of a 99%-complete PC-to-device file copy. It is evidence that the updater had already accepted the package-copy/update-start stage and was waiting for device-side completion.

## SendFWUpdateCommand flow

Reverse engineered flow in `FWUpdaterCom.dll`, including the MSVC exception tables:

1. Build `<drive>:\MSFWUPGR.UPG`.
2. `CopyFileA` the selected official UPG to that path.
3. If `CopyFileA` fails, obtain `GetLastError()` (including explicit handling of `ERROR_DISK_FULL / 0x70`) and call an internal exception helper.
4. The helper reaches `RaiseException`. The `SendFWUpdateCommand` FuncInfo (`0x1000CF30`) maps the exception to catch handler `0x10005287`.
5. That catch handler returns a continuation at `0x1000529A`, which performs cleanup/error return. It bypasses the `FC/04` builder at `0x10005222`.
6. On the normal success path, send Sony vendor command `FC/04` as a 12-byte CDB with no data payload.
7. Return success to the UI, which then waits for the Walkman to restart/reappear.

`FC/04` is therefore an update-start command, **not a PC-side firmware transport**. A failed PC-side package copy does not normally reach it.

For Issue #1, reaching the GUI's 99% wait is important evidence: that wait occurs only after `SendFWUpdateCommand` returned success. This strongly suggests the original UPG copy and update-start stage completed far enough for the UI to begin its post-start wait. The failure is therefore more likely in device-side update processing, reboot, or re-enumeration than in the visible PC-side file copy itself.

Blindly re-sending `FC/04` is still unsafe. The first update-start may already have partially modified firmware or metadata, and the exact on-device package/update state is not recoverable through the current `3A00` mass-storage path.

## Windows 7 x64 assessment

The 2005 firmware updater was released for Windows 98/Me/2000/XP-era systems. Sony's later Windows 7 compatibility page does not list NW-E405/E407 and says unlisted models were not planned for Windows 7 support. The old application stack is not a supported Windows 7 environment.

However, the updater does not simply reject Windows 7. Its internal OS classifier maps NT 6.x into the same high-level backend selection path used by later NT systems. User group membership also affects backend selection; an Administrator can be routed to the direct-drive SCSI backend.

So Windows 7 x64 was an unsupported and risky environment, but it is not sufficient by itself to explain this failure. The 99% evidence suggests the updater reached and returned successfully from the package-copy/update-start stage. Windows 7 x64 remains a plausible contributing factor in post-update re-enumeration or legacy-driver behavior. Low free space is also plausible, specifically the range where the 2.13 MB package fits but Sony's recommended ~3 MB working-space requirement is not met; this remains an inference rather than a proven root cause.

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


## v0.6 No-Media logical rescue

`READ CAPACITY(10)` returning `3A00` does not prove that every `READ(10)` must fail. v0.6 therefore performs one explicitly bounded experiment on an exact Issue #1 state match: `READ(10)`, LBA 0, one 512-byte block. If that succeeds, it treats the result as evidence that the logical media path is partly reachable despite the capacity command failure.

The tool then parses FAT12/16/32 BPB data directly or follows an MBR partition start to a FAT boot sector. A derived geometry is accepted only when the BPB is internally plausible and the resulting image size is <= 2 GiB. Bulk rescue remains READ(10)-only.

After imaging, the tool first extracts root `MSFWUPGR.UPG` by following the FAT cluster chain. If directory/FAT metadata is damaged, it also scans the raw image for the official UPG header tuple (`UPGR_FMT`, `SONY`, `00100000`) and cuts a 2,131,380-byte candidate for SHA-256 comparison. This is intended to distinguish a complete official package from a damaged/stale package without writing anything to the player.

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

## v0.7 Recovery Ladder

v0.7 combines the most useful findings from earlier releases instead of adding unrelated probes:

- v0.3.1: original-updater-matched FC/03 transport parameters.
- v0.5.1: corrected MSVC exception/control-flow audit, immediate intent/result logging, official package verification.
- v0.6.1: gated No-Media LBA0 READ(10), FAT/MBR imaging, root UPG extraction and official hash comparison.
- v0.7: action ladder using those results.

### Stage 2: A3/A4

The reference implementation in `tatsuyai713/sonydb-gui` documents a sequence captured from Sony MP3 File Manager talking to an NW-E405. A3 (`A3 00 00 00 00 00 00 BC 00 14 30 00`) with a fixed 20-byte `00 12 00...` DATA OUT selects an 18-byte Device-ID record. A4 (`A4 00 00 00 00 00 00 BC 00 12 3F 00`) reads the record. v0.7 hardcodes this one DATA OUT sequence and exposes no arbitrary outbound-SCSI interface.

### Stage 3: FC/04 retry gate

FC/04 is no longer treated as a generic recovery command. v0.7 makes it reachable only if the rescued FAT root contains an exact official Japanese v2.0 UPG, the inferred pre-copy free-space condition is not below Sony's ~3 MB requirement, the official updater EXE is verified in-session, the live device still matches the Issue #1 3A00 + known-FC03 state, and a second immediate preflight passes. Two user confirmations are required. The tool sends one no-data FC/04 and then monitors re-enumeration without sending another update/write command.

### Privacy

Full CDB JSONL, metadata, DvID, sectors, images and recovered UPG files are private evidence. v0.7 generates a separate public report containing only status flags and hashes.
