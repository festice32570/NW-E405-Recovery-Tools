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

## Deep transport/package audit (2026-09-26)

### `SONYICD` is transportable over standard Windows SPTI

The `SONYICD` discovery was followed through `IcdMSCom.dll` all the way to a standard Windows SCSI pass-through backend, rather than stopping at the generic vendor-CDB builder.  The DLL contains multiple historical backends/paths (`\\.\scsipath%d`, `\\.\SONYSPTI`, a drive-letter path, and legacy Windows code), but the command semantics sit above them.

One backend uses a common routine at the exact analyzed image address `0x10001080` that builds a `SCSI_PASS_THROUGH`-style request (`Length=0x2c`, `SenseInfoLength=0x12`, `SenseInfoOffset=0x30`) and invokes `DeviceIoControl` with `0x4D014`.  Three thin wrappers feed the same routine with mode values 2/1/0:

- wrapper `0x10002540`: mode 2, no data;
- wrapper `0x10002560`: mode 1, DATA IN;
- wrapper `0x10002580`: mode 0, DATA OUT.

The generic `FC 00 <command> "SONYICD" <length>` builder dispatches command families to those no-data / data-in / data-out virtual methods.  This materially strengthens the case that the exact `SONYICD` Get CDBs can be issued by the recovery tool's existing Windows SPTI transport even when the normal logical media is `3A00`, because they are ordinary SCSI CDBs at this layer rather than opaque calls that require Sony's proprietary application stack.

The best first E405-native candidate is therefore:

`FC 00 01 53 4F 4E 59 49 43 44 00 74` — `GetTargetIdentifier`, DATA IN `0x74`.

A secondary candidate is:

`FC 00 02 53 4F 4E 59 49 43 44 00 48` — `GetPreferenceInfo`, DATA IN `0x48`.

The current release does **not** send either command yet.  A pure static builder/specification is in `tools/sonyicd_spec.py`; it performs no device I/O.  `tools/icdmscom_protocol_audit.py` now pins the command builder, SPTI structure, direction wrappers, family dispatch and response-parsing evidence against the exact Sony DLL.

`GetTargetIdentifier` checks byte `response[0x0F]` as a device-side status result.  The successful-response parser copies two strings and converts a mixture of 16-bit and 32-bit fields using `ntohs`/`ntohl`.  Until every field is identified, the raw 0x74-byte response must be treated as PRIVATE/device-specific evidence.  A public report may safely expose command outcome, SCSI/Sense result, response length and a SHA-256 of the raw response, but not the raw strings/identifiers.

The `0x04/0x05` GetRevokeList commands are read-only but are low-value recovery probes and appear DRM/revocation-related; they should not be sent merely because they exist.  The `0x41..0x45` Set family is DATA OUT and must remain disabled on the failed unit.  `0x80 Reset` is no-data but state-changing and likewise is not a diagnostic probe.

### FrankPACAPI: QuickFormat is not the missing No-Media recovery transport

Deeper tracing of `_CFrankFileSystem_StartQuickFmt` and its worker changed the interpretation of the MP3 File Manager's format support.  The worker calls ordinary filesystem functions including `GetDiskFreeSpaceExA`, `DeleteFileA`, `RemoveDirectoryA`, `CreateDirectoryA`, and path/directory helpers.  It builds and manipulates filesystem-format operation structures and waits on worker events.  Current evidence therefore points to a mounted/logical-filesystem formatting workflow, not a hidden raw-NAND erase/program path that bypasses `3A00 MEDIUM NOT PRESENT`.

Quick/Full erase strings remain useful historical evidence about application features, but invoking QuickFormat on the failed unit is neither justified nor safe.  This branch is now lower priority than the E405-native read-only vendor protocol.

FrankPACAPI does contain another bounded read-only SCSI operation: a `MODE SENSE(10)` CDB beginning `5A 00 3F` with an eight-byte allocation.  It passes through the shared SCSI transport and is used as a capability/status check before additional logic.  It may be useful later for state classification, but it has less direct recovery value than `SONYICD GetTargetIdentifier` and should not be added simply to increase probe count.

### UPG payload block-boundary observations

Aligned comparisons were extended beyond whole-record hashes.  Important observations from the available official packages are:

- E40X-J and E50X-J record 3 are byte-for-byte identical for all `0x10518` bytes.
- A600-J and A600-C record 3 are byte-for-byte identical for all `0x10510` bytes.
- E40X and normal A600 record 3 remain identical through exactly `0x750` bytes and then diverge; no later same-position 8-byte block re-synchronizes.
- Normal type-4 records from E40X, E50X, A600-J and A600-C all begin with the same eight bytes `A3 50 92 8E 14 8B 49 E1`; the next aligned eight-byte block differs, and no later same-position eight-byte block matches in the tested pairs.
- Record-3 payloads begin with `31 43 DF A9 85 B9 B6 13` across the compared packages.
- The A600 BOOT21 type-6 large record begins with a different fixed-looking eight-byte value (`FD 79 EA 57 50 FE F7 2C`) and differs from the normal type-4 record from byte zero.

Divergence starting exactly at eight-byte boundaries, followed by no same-position block re-synchronization, is **consistent with** a deterministic chained transform with a 64-bit granularity (a CBC-like property is one plausible example).  It does not prove that the data is encrypted, does not identify DES/3DES or any other cipher, and does not establish a key/IV layout.  Compression plus encryption/obfuscation could produce similar observations.

The repeated eight-byte prefix on all normal type-4 records is particularly interesting: it behaves more like a per-record-type preamble/IV-like value than ordinary model-specific firmware bytes.  Again this is a structural hypothesis only.

The recurring `+0x18` size is also notable.  Removing 24 bytes from the A600 BOOT21 type-6 record leaves exactly `0x200000` bytes (2 MiB); removing 24 bytes from a normal type-4 record leaves `0x1F8000`.  Record-3 sizes similarly become clean eight-byte-aligned core sizes.  Simple MD5-of-record and CRC32 checks do not explain a 16-byte trailer, so the 24 bytes must not yet be labelled as a specific IV/hash/signature structure.  `tools/upg_block_compare.py` records the reproducible aligned-block observations without claiming a cipher.

The official PC updater binaries do not contain the `UPGR_FMT` magic or E40X model identifier and do not expose an obvious package decrypt/decompress path; they copy the UPG as a file before `FC/04`.  The strongest current interpretation is therefore that UPG parsing/verification/transformation occurs on the player side.  That is another reason a modified PC updater is not, by itself, a No-Media force-flash transport.

### E40X overseas package comparison recovered from Sony update infrastructure

The overseas E40X package is no longer a missing artifact. The US `NW-E40X_V2_0C.EXE` was recovered directly from Sony's `hav.update.sony.net` update infrastructure and retained only in the private research tree. Its SHA-256 is `a38cc219405b0697c660bc2b58b464f4e2f2e9f1c9449adabcd127ee46db58e8`; the contained US package is `MSFWUPGR_NW-E40X_200C.UPG` (INI version 2.0.80.0, SHA-256 `a8901044a8314a80f4ad9c9b92f8b3789595d4af32c6ec84b3bd4cdc57941df4`). A separate European package contains `MSFWUPGR_NW-E40X_201C.UPG` (INI version 2.0.81.0, SHA-256 `b4057322f5112136b996bcd5695784b0665ce14daff30cbf85d003088aa0e12c`).

The EU 201C and Japanese 201J UPGs have identical records 1, 2 and 3 byte-for-byte. Their type-4 records have the same `0x1F8018` length and the same first eight bytes, then diverge without same-position 8-byte re-synchronization; record 5 also differs. The older US 200C package additionally has a shorter type-3 record (`0x10430` instead of `0x10518`) and diverges from the 201 packages after a common `0x750`-byte prefix. This makes record 3 look revision-dependent in the observed samples, while record 4 carries the stronger region/model-specific payload difference. Those are structural observations, not a decoded semantic map.

Because valid official E40X variants do not all share the Japanese section lengths, `tools/upg_analyzer.py` now separates generic known-container validity from `japanese_layout_ok`. The exact Japanese recovery approval remains unchanged: model, Japanese layout, file size and the pinned Japanese SHA-256 must all match before `APPROVED_E40X_J` is true.

### Hardware boundary after software-path review

The NW-E403/E405/E407 service manual itself identifies `TP404 TXD1`, `TP405 RXD1`, `TP412 DEBUG`, `TP409 XBOOT`, and `IC400 CXR704060-202GA`.  Its block diagram also separates `Q501/Q502 NAND FLASH RAM` from `IC450 NOR FLASH / SRAM`.  CXR704060 documentation independently confirms a dedicated flash-memory interface, a separate 16-bit external bus, and UART channel 1 (`TxD1`/`RxD1`).

`IC450 S99-50082` is cross-referenced in Spansion material to the S71AL016D02 family, a 16-Mbit Flash + 2-Mbit SRAM MCP, i.e. a 2-MiB flash die.  The numerical match to the BOOT21 `0x200000` core-sized observation is important supporting evidence, but it still does not establish the record-to-physical-address map.

A related CXR704060-based NW-HD3 service manual names `PK2/XBOOT` as a boot-mode selection input and shows that product's relevant I/O rail as +1.8 V.  That proves the signal's role in a closely related implementation, **not** the safe electrical level or strap procedure for NW-E405.  E405 XBOOT polarity, reset timing, pin rail, UART baud/protocol and ROM monitor behavior remain unverified.  No grounding/driving instruction should be issued until the E405 electrical path is resolved from its own schematic/measurement.

### Revised recovery research priority

The software path should now be exhausted in this order before moving to hardware boot mode:

1. Use v0.8.2 to preserve the existing Stage 2A/2B evidence and add the separately gated E405-native `SONYICD 0x01 GetTargetIdentifier` DATA-IN result.
2. Interpret the private 0x01 response only after the real unit result is available; public reporting remains status/hash only.
3. Consider `SONYICD 0x02` only if 0x01 establishes that the SONYICD service path is alive and the extra information has a concrete recovery purpose.
4. Keep FrankPACAPI `A4/BC/33` static-only until/unless a 1028-byte transport extension is justified by the preceding results; keep QuickFormat/Set/Reset operations disabled.
5. Only if the remaining software vendor/service paths are exhausted, move to XBOOT/UART/boot-ROM research with measured electrical conditions first.

This supersedes the earlier shortcut `FB + A3/A4 fail -> XBOOT`.

## MP3 File Manager low-level cross-check: CopyTool + FrankPACAPI (2026-09-26)

### CopyTool independently confirms the NW-E405 A3/A4 Device-ID sequence

Static analysis of Sony MP3 File Manager's `CopyTool.exe` independently reproduces the same A3/A4 sequence previously known from the SonyDB capture/implementation. This is stronger evidence than relying on the third-party capture alone.

`CopyTool.exe` builds the fixed outbound select command:

`A3 00 00 00 00 00 00 BC 00 14 30 00`

with exactly 20 bytes of outbound data beginning `00 12` and otherwise zero-filled in the observed construction. It then uses CopyTool's outbound SCSI transport. The subsequent read path builds:

`A4 00 00 00 00 00 00 BC 00 12 3F 00`

for 18 bytes DATA IN and retries the inbound transaction once if the first call fails. `tools/copytool_dvid_audit.py` pins these instructions without performing device I/O.

### FrankPACAPI contains a second, larger A4/BC read command

Sony's `FrankPACAPI.dll` (SHA-256 `1356a2a96235a3a4319ba0dbcb1b8ede4a21cb786f5ea7e3ff214bb56470a802`) contains exactly two uses of one 12-byte CDB-builder pattern. Both construct:

`A4 00 00 00 00 00 00 BC 04 04 33 00`

with `0x0404` (1028) bytes returned from the device and subcommand `0x33`. One path calls Frank's direct inbound command routine; the other is in Sony source path `koDeviceFormatFrankBehavior.cpp` and explicitly logs failures from `m_pclProtocol->ExecCommandIn()` and `m_pclProtocol->GetDeviceInfo()`. The Type Library independently names the API split as `ExecCommand`, `ExecCommandIn`, and `ExecCommandOut`, with parameters `ulCommandSize`, `pbyteCommand`, Sense/ASC/ASCQ, and device-to-host vs host-to-device data sizes/buffers. Therefore A4/BC/33 is firmly a DATA-IN/read-only query in Sony's implementation, not the format/erase action itself.

In the direct implementation, the 1028-byte response starts at a local buffer whose byte at raw offset `0x0C` has bit 7 extracted and logged as `iDeviceMode`. A caller maps the resulting 0/1 value to Sony behavior types 2 or 4. This makes `A4 ... 33` a strong candidate for a device-mode/behavior query used to choose formatting/device behavior. The exact semantic label of every response field remains unknown.

### ATRACAD2 ties the query to the NW-E405 family

Frank's lower device class issues a standard 56-byte INQUIRY and parses the normal identification fields. In addition to Vendor/Product/Revision it extracts the 8-byte vendor-specific field at INQUIRY offset `0x24`. The Frank binary contains explicit family identifiers `ATRACHD1` and `ATRACAD2`.

The path that precedes the A4/BC/33 query scans device indices and compares the extracted identification string against `ATRACAD2` before using the query. The real failed NW-E405 INQUIRY captured by this project contains `ATRACAD2` at that same vendor-specific region. This substantially strengthens the case that the A4/BC/33 query is applicable to the NW-E405/NWWM MEM AAD2 family rather than being an unrelated Hi-MD-only command.

A separate `koDeviceFormatFrankBehavior.cpp` path first compares a normal `GetDeviceInfo` string against `ATRACHD1`; that family can be assigned one behavior directly, while the non-HD path falls through to the A4/BC/33 query. Separately, `koDeviceFormatFrankLocal.cpp` explicitly branches on `ATRACAD2` for local CID/SID handling. Sony therefore treats these strings as real device-family selectors internally.

### Transport and current No-Media state

Frank's Windows-NT path normally opens a drive-letter-style device (`\\.\\A:` template) and uses standard Windows SCSI pass-through (`IOCTL_SCSI_PASS_THROUGH_DIRECT`, `0x4D014`). An older/alternate path contains `\\.\\SONYSPTI`. The failed unit currently exposes no usable drive letter, so the original MP3 File Manager high-level path may never reach the command even if the device itself would accept it. The Recovery Tool, however, already opens the exact `SONY / NWWM MEM AAD2` disk interface directly, so a future bounded read-only A4/BC/33 compatibility probe can use the same standard SPTI transport without requiring a mounted volume.

Frank's generic retry wrapper treats exact packed Sense `02/3A/00` (`Medium Not Present`) as a terminal/non-retryable condition, while some other NOT READY / UNIT ATTENTION conditions are retried. This confirms that Sony's normal media path regards the current state as a hard media-presentation failure; it does not establish that the separate A4/BC service query is blocked by that state.

`tools/frank_a4_behavior_audit.py` pins the A4/33 construction, read-only transport evidence, response-bit extraction, behavior mapping, standard SPTI support, and 3A00 handling. No device I/O is performed by the audit.


## v0.8.2 decision: E405-native SONYICD 0x01 becomes Stage 2C (2026-09-26)

The next live read-only probe is now selected: `SONYICD 0x01 GetTargetIdentifier`, not FrankPACAPI `A4/BC/33`. The choice is based on bounded implementation evidence rather than probe count. `0x01` is from the E405-era Sony MP3 File Manager itself, uses the already-confirmed standard SPTI DATA-IN path, requests only `0x74` (116) bytes, and fits the Recovery Tool's existing 128-byte response buffer without transport redesign. The Frank A4/BC/33 query remains useful static evidence but returns 1028 bytes and is tied to format-behavior selection, so it stays deferred.

Static control-flow evidence in `IcdMSCom.dll` now pins the important failure semantics. `GetTargetIdentifier` first checks the generic transport call. After a transport success it reads `response[0x0F]`; any nonzero application status is returned before Sony's identifier/string/numeric field parser runs. Field decoding occurs only when that status is zero. `tools/icdmscom_protocol_audit.py` now asserts this ordering in addition to command, length, direction and SPTI evidence.

Stage 2C therefore sends exactly `FC 00 01 53 4F 4E 59 49 43 44 00 74` once, DATA IN only, after its own explicit user confirmation and fresh Issue #1 state preflight. The transport now records the returned `SCSI_PASS_THROUGH_DIRECT.DataTransferLength`; application status is inspected only for SCSI GOOD plus an exact 116-byte transfer. A complete raw response is written only to a PRIVATE blob. The public report exposes the SCSI summary, one-byte Sony application status and response SHA-256, never the strings or decoded identifier fields.

No `SONYICD Set 0x41..0x45`, `Reset 0x80`, format/erase, standard SCSI WRITE, or arbitrary DATA OUT path was added. The only explicit DATA OUT implementation remains the pre-existing fixed A3 select. The separately gated FC/04 recovery-resume path is unchanged.
