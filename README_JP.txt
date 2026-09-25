NW-E405 Recovery Probe v0.1
================================

Purpose
-------
For a Sony NW-E405 that failed a firmware update and now shows MEMORY ERROR /
"No media" in Windows. This first-stage tool only asks the device questions.
It does not format, erase, write sectors, copy firmware, or start a firmware update.

Target environment
------------------
Windows 7 (32-bit or 64-bit), PowerShell 2.0+, .NET Framework available.
No Python/Linux/SonicStage installation is required for this diagnostic pass.

How to run
----------
1. Disconnect other USB flash drives / card readers if practical.
2. Connect the broken NW-E405 directly to a USB port (avoid USB hubs).
3. Right-click RUN_DIAGNOSTIC.cmd -> Run as administrator.
4. Wait for the four standard SCSI tests and one Sony read-only test.
5. A file named NW-E405_diag_YYYYMMDD_HHMMSS.txt will appear in this folder.
6. Send that TXT log back for analysis.

What the tool checks
--------------------
- USB/PnP presence for VID_054C & PID_01FB
- Whether Windows created a physical disk object
- Standard SCSI INQUIRY
- TEST UNIT READY and sense data
- REQUEST SENSE
- READ CAPACITY(10)
- Sony vendor command 0xFC / subcommand 0x03, reverse-engineered from
  Sony's official 2005 FWUpdaterCom.dll. In the updater this command is used
  to read firmware/version information.

Safety
------
This Stage 1 build is intentionally read-only.
DO NOT use Windows Format, Disk Management initialize, diskpart clean, chkdsk /f,
or third-party formatting tools on the Walkman.

Interpretation examples
-----------------------
INQUIRY works but READ CAPACITY returns NOT READY / 3A/00:
  USB + SCSI command path is alive, but the device firmware reports no medium.

Sony 0xFC/0x03 also works:
  Very useful. The vendor command processor is alive even though the media is
  unavailable. A Stage 2 recovery command may be possible.

Nothing can open \\.\PHYSICALDRIVEx:
  Send the log anyway. We may need to use Sony's original SONYSPTI path instead.

Important
---------
The experimental Sony command that starts an update (0xFC / subcommand 0x04)
is NOT included in Stage 1. We should inspect the Stage 1 log first.
