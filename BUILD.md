# Building the GUI

The GUI is a native Win32 C application targeting 32-bit Windows.

## Compatibility target

- Windows 7 and later
- x86 executable (also runs under WoW64 on 64-bit Windows 7)
- MSVCRT runtime
- No .NET / PowerShell / Python dependency at runtime

## Toolchain used for v0.2-dev

llvm-mingw, MSVCRT variant, targeting i686-w64-windows-gnu.

Example:

```sh
i686-w64-mingw32-windres src/app.rc -O coff -o src/app.res

i686-w64-mingw32-clang \
  -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 \
  -Os -s -municode -mwindows \
  src/NW-E405-Recovery-Tool.c src/app.res \
  -o NW-E405-Recovery-Tool.exe \
  -lsetupapi -lshell32 -lgdi32 -luser32 -lkernel32 -luuid
```

The embedded manifest requests administrator privileges because Windows may require them for SCSI pass-through access.
