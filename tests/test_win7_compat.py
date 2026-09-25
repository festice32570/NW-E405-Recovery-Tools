from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
SRC=(ROOT/'src/NW-E405-Recovery-Tool.c').read_text(encoding='utf-8')
MAN=(ROOT/'src/app.manifest').read_text(encoding='utf-8')
BUILD=(ROOT/'BUILD.md').read_text(encoding='utf-8')
WIN7_GUID='{35138b9a-5d96-4fbd-8e2d-a2440225f93a}'

# APIs/features that would accidentally raise the minimum OS above Windows 7
# if directly imported/used in this small Win32 utility.
POST_WIN7_FORBIDDEN=(
    'GetSystemTimePreciseAsFileTime',
    'SetProcessDpiAwareness',
    'GetDpiForWindow',
    'SetThreadDpiAwarenessContext',
    'GetSystemCpuSetInformation',
    'SetProcessInformation',
    'GetFileInformationByHandleExFromApp',
    'CreateFile2',
)

def test_manifest_explicitly_supports_windows7():
    assert WIN7_GUID in MAN
    assert 'processorArchitecture="x86"' in MAN
    assert 'requireAdministrator' in MAN

def test_build_target_is_windows7_and_x86():
    assert '-D_WIN32_WINNT=0x0601' in BUILD
    assert '-DWINVER=0x0601' in BUILD
    assert 'i686-w64-mingw32' in BUILD

def test_no_known_post_win7_api_creep():
    for api in POST_WIN7_FORBIDDEN:
        assert api not in SRC, api

def test_no_dotnet_or_powershell_runtime_dependency():
    low=(SRC+'\n'+BUILD).lower()
    assert 'system.management' not in low
    assert 'powershell.exe' not in low
    assert 'mscoree.dll' not in low
