# Building NW-E405 Recovery Lab

Native Win32 C, 32-bit (`i686`) for Windows 7 x86/x64 (WoW64). No .NET, PowerShell or Python is required at runtime.

v0.5-dev is a read-only device-side forensic/preflight build. It links miniz only to verify/extract a user-selected official Sony self-extracting updater on the PC.

```sh
i686-w64-mingw32-windres src/app.rc -O coff -o src/app.res

i686-w64-mingw32-clang \
  -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 \
  -Os -s -municode -mwindows \
  src/NW-E405-Recovery-Tool.c src/fw_package.c \
  third_party/miniz/miniz.c third_party/miniz/miniz_tinfl.c \
  third_party/miniz/miniz_tdef.c third_party/miniz/miniz_zip.c \
  src/app.res -Ithird_party/miniz \
  -o NW-E405-Recovery-Lab.exe \
  -lsetupapi -lcfgmgr32 -lshell32 -lgdi32 -luser32 -lkernel32 -luuid \
  -lcomdlg32 -ladvapi32
```

The manifest requests administrator privileges because Windows may require them for SCSI pass-through. This permission does not imply media writes; release validation rejects SCSI DATA OUT, FC/04 and standard SCSI WRITE opcodes.

## Validation

```sh
python3 tests/run_tests.py
python3 tests/validate_release.py
python3 tools/original_updater_audit.py /path/to/FWUpdaterCom.dll
```

The original-updater audit is pinned to the exact analyzed `FWUpdaterCom.dll` SHA-256 and verifies the low-free-space control-flow finding before relying on it.
