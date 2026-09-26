# Building NW-E405 Recovery Lab

Native Win32 C, 32-bit (`i686`) for Windows 7 x86/x64 (WoW64). No .NET, PowerShell or Python is required at runtime.

v0.8.3-dev is a Windows 7-targeted Recovery Ladder research build. Diagnostics, imaging, the A600 FB probes, E405-native SONYICD 0x01, and the separately gated authentic E40X FC/05+roga Stage 2D are DATA-IN/read-only; the only DATA OUT implementation remains the fixed A3 Device-ID select sequence. FC/04 is reachable only behind the verified-package/free-space/official-firmware/current-state gates. It links miniz only to verify/extract a user-selected official Sony self-extracting updater on the PC.

```sh
i686-w64-mingw32-windres src/app.rc -O coff -o src/app.res

i686-w64-mingw32-clang \
  -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 \
  -Os -s -municode -mwindows \
  src/NW-E405-Recovery-Tool.c src/fw_package.c \
  third_party/miniz/miniz.c third_party/miniz/miniz_tinfl.c \
  third_party/miniz/miniz_tdef.c third_party/miniz/miniz_zip.c \
  src/app.res -Ithird_party/miniz \
  -o NW-E405-Recovery-Tool.exe \
  -lsetupapi -lcfgmgr32 -lshell32 -lgdi32 -luser32 -lkernel32 -luuid \
  -lcomdlg32 -ladvapi32
```

The manifest requests administrator privileges because Windows may require them for SCSI pass-through. This permission does not imply media writes; release validation rejects SCSI DATA OUT, FC/04 and standard SCSI WRITE opcodes.

## Validation

```sh
python3 tests/run_tests.py
python3 tests/validate_release.py
python3 tools/original_updater_audit.py /path/to/FWUpdaterCom.dll /path/to/FWUpdater.exe
```

The original-updater audit is pinned to the exact analyzed `FWUpdaterCom.dll` and `FWUpdater.exe` SHA-256 values. It verifies the MSVC exception-handler path for copy failure and separately pins the post-start 99% progress/timer behavior.

After building the final EXE, validate the PE itself:

```sh
python3 tests/validate_built_pe.py
```

This checks that the artifact is 32-bit Win32 GUI, uses only Win7-era system DLLs, and has no .NET/UCRT/VCRuntime dependency.
