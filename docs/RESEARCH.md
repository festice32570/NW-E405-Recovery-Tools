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

## A600 extended-updater comparison (2026-09-26)

Sony's official `NW-A600_V2_0.exe` is a useful same-generation comparison target. The exact package analyzed locally has SHA-256 `3ea05d6601e0e1c7a039f1c88fcc9cca9a49682cd87ef5e604bbc570ec89d552`; its `FWUpdaterCom.dll` has SHA-256 `56aa815bbe6e3441bd3e3168e9511dce94f2e0927167f1671f1a9a8c40ca58bf`.

Unlike the E40X updater, the A600 package contains `PBR512.dat`, `PBR1G.dat`, and `PBR2G.dat`, and its INI uses `StorageMediaFormatType` and `PBRFile`. The DLL exposes an `IFWUpdaterComExt` interface including `CheckStorageFormatType`, `SendFWUpdateCommandExt`, `DeleteUpdateFileExt`, and `GetDeviceIdExt`.

Static analysis of the exact DLL shows that the storage-format check builds SCSI READ(10) (`0x28`) with a 512-byte transfer. It first reads LBA0, then takes the DWORD at offset `0x1C6` of that sector (the first MBR partition entry's starting-LBA field), converts it to the CDB LBA field, and reads that sector too. It then opens the model-specific PBR file on the PC and compares BPB portions of the device PBR and the template: 12 bytes starting at offset `0x0B` and 8 bytes starting at offset `0x1C`.

The three PBR files are 512-byte FAT16 boot-sector templates with `55 AA` signatures and model/capacity-specific BPB geometry. This strongly supports interpreting `CheckStorageFormatType` as a FAT16 geometry/PBR compatibility check rather than a generic disk-capacity test.

`SendFWUpdateCommandExt` imports and uses `CopyFileA`, and its extended update path also contains the Sony `FC/04` update-start builder. No explicit standard SCSI WRITE(10) (`0x2A`), WRITE(12) (`0xAA`), WRITE BUFFER (`0x3B`) or `0x3F` CDB builder was found in this DLL. Current evidence therefore favors a design where the PC stages files and invokes the player-side update mechanism rather than writing the PBR with a standard raw-sector WRITE command from Windows. This does not yet prove the exact device-side handling of the PBR file.

The E40X updater has no `PBR`, `StorageMediaFormatType`, `CheckStorageFormatType`, `SendFWUpdateCommandExt`, `DeleteUpdateFileExt`, `GetDeviceIdExt`, or `FWPackageWritePathName` strings. The extended mechanism appears to have been added in the A600-generation updater rather than being exposed in the E405 updater.

Reproducible checks are in `tools/a600_ext_audit.py`; the Sony binaries themselves are not committed.

## Issue #1 v0.7 public report result (2026-09-26)

The returned `NW-E405_PUBLIC_REPORT_20260926_040236.txt` established the next boundary on the actual failed unit:

- exact USB/SCSI identity matched;
- TUR remained `3A00 Medium Not Present`;
- READ CAPACITY remained `3A00 Medium Not Present`;
- the known FC/03 1.x response still matched;
- the bounded direct `READ(10)` of LBA0 was also unreadable.

This closes the ordinary logical-media rescue branch for the current device state: FAT/MBR/PBR traversal, logical imaging, root `MSFWUPGR.UPG` recovery, and any free-space estimate cannot be performed through the normal SCSI logical-media path while LBA0 remains unreadable.

Two v0.7 public-report fields were semantically ambiguous and must not be over-interpreted. `Root MSFWUPGR.UPG exact official match: NO` did not mean a compared package mismatched; the package was never reachable because LBA0 could not be read. `A3/A4 Device-ID query: NOT ACQUIRED` did not distinguish user decline, no attempt, A3 failure, or A4 failure.

v0.8.1-dev addresses this evidence gap without requiring private logs to be posted publicly. The PUBLIC_REPORT records safe command-result summaries (`IOCTL`, Win32 status, SCSI status and Sense Key/ASC/ASCQ), distinguishes A3 and A4, records Stage 2A/2B live-state preflight components, and uses explicit NOT CHECKED / NOT EVALUABLE wording when logical media is unreadable. Raw responses and private evidence remain excluded from the public report.

## Firmware-package / failed-unit cross-check (2026-09-26)

The v0.7 real-device result (`TUR=3A00`, `READ CAPACITY=3A00`, direct LBA0 `READ(10)` unreadable, known FC/03 still alive) was cross-checked against the official E40X/E50X/A600 UPG structures and Sony MP3 File Manager binaries.

### UPG record comparison

The E40X Japanese v2.0 package uses descriptors `(1,0x50) (2,0x30) (3,0x10518) (4,0x1F8018) (5,0x4)`. E50X has the same lengths; records 2 and 3 are byte-for-byte identical to E40X, while record 4 differs after an eight-byte common prefix. This is evidence that some packaged component(s) are shared between E40X/E50X while the large type-4 record is substantially model-specific. The exact physical flash mapping is not yet decoded.

A600 provides a boot-version contrast. A normal `BootstrapVersion=2.1` device selects a package whose large descriptor is `(type 4, 0x1F8018)`. The `BootstrapVersion=2.0` entry explicitly selects `NW_A600_2.00.00J_BOOT21.UPG`, whose corresponding descriptor is `(type 6, 0x200018)`. The length difference is exactly `0x8000` (32 KiB); subtracting `0x18` from the record lengths yields `0x1F8000` versus exactly `0x200000` (2 MiB). This strongly suggests a relationship between the BOOT-aware package and a full 2 MiB flash-sized image, while the normal package excludes a 32 KiB region. It does **not** yet prove exact physical addresses, that type 6 literally means "bootloader", or the transformation/encryption layout of the high-entropy payload.

This makes the failed E405 state consistent with a layered failure: enough boot/control code survives to enumerate USB, answer SCSI/FC03 and display `MEMORY ERROR`, while logical-media initialization fails before a sector can be exposed. It does not prove the entire NOR is intact or that the NAND itself is physically damaged. The still-1.x FC03 response is evidence that final version/commit state was not advanced, not proof that every main-firmware byte remained at v1.0.

### Sony MP3 File Manager IcdMSCom vendor family

Reverse engineering of the official MP3 File Manager `IcdMSCom.dll` found a generic vendor CDB builder:

`FC 00 <command> 53 4F 4E 59 49 43 44 <length_be16>` (`FC 00 <command> "SONYICD" <length>`).

The command's top two bits select one of three transport methods. Named call sites establish the semantics strongly:

- `0x00` family: Get/read path. `0x01 GetTargetIdentifier` (0x74 bytes), `0x02 GetPreferenceInfo` (0x48 bytes), `0x04/0x05 GetRevokeListST` (0x1F8 bytes each).
- `0x40` family: Set/data-out path. `0x41 SetUserNameDevice`, `0x42 SetPreferenceMenu`, `0x43 SetUniqueID`, `0x44/0x45 SetRevokeListST`.
- `0x80`: `Reset`, no data payload.

This proves that the E405-era Sony software contains a richer vendor-command family beyond the already known A3/A4 and updater FC03/04/05/09 commands. The read-family commands are high-value candidates for a future safe recovery probe, but they are **not yet enabled in the Recovery Tool**. Raw returned identifiers/DRM structures may be device-unique and must remain private; a future public report should expose only status/Sense and hashes or non-identifying decoded fields.

The MP3 File Manager `FrankPACAPI.dll` also contains `_CFrankFileSystem_StartQuickFmt`, FAT/no-filesystem medium enums, and Quick/Full erase frameworks. Current static analysis shows the QuickFormat worker is layered through filesystem/format helper structures and does not yet prove a No-Media-bypassing raw flash command. Therefore QuickFormat must not be invoked on the failed unit until its lower transport is mapped and its destructive operations are separated from read-only/status operations.

Updated software-recovery research order after this cross-check: (1) current v0.8.1 read-only FB + A3/A4 evidence, (2) map and cautiously add proven read-only `SONYICD` Get commands, (3) finish FrankPACAPI QuickFormat/device-control transport analysis, then (4) XBOOT/boot-ROM only if the software service paths are exhausted. The earlier shortcut "FB+A3/A4 fail -> XBOOT" was premature.
