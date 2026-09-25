from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
src = (root / "src" / "NW-E405-Recovery-Tool.c").read_text(encoding="utf-8")

checks = {
    "exact NW-E405 USB ID": 'VID_054C&PID_01FB' in src,
    "exact Sony SCSI identity": 'NWWM MEM AAD2' in src,
    "known Issue #1 FW info gate": '{0x01,0x00,0x0D,0x00,0x20,0x02,0x00,0x00}' in src,
    "No Media gate": 'sense[12] == 0x3A' in src and 'sense[13] == 0x00' in src,
    "recovery revalidation": 'OpenIssue1RecoveryTarget' in src,
    "default confirmation is No": 'MB_DEFBUTTON2' in src,
    "no SCSI DATA OUT": 'SCSI_IOCTL_DATA_OUT' not in src,
    "single FC/04 assignment": src.count('cdb[2] = 0x04') == 1,
    "FC/04 has no data payload": 'SendCdb(h, cdb, 12, 0)' in src,
    "FC/03 remains read-only": src.count('cdb[2] = 0x03') >= 2,
}

failed = False
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL"), name)
    failed |= not ok

# Guard against standard SCSI write opcodes accidentally appearing in CDB assignment form.
for opcode in (0x2A, 0xAA, 0x3B, 0x3F):
    pat = rf'cdb\[0\]\s*=\s*0x{opcode:02X}\b'
    ok = re.search(pat, src, flags=re.I) is None
    print(("PASS" if ok else "FAIL"), f"no standard write opcode 0x{opcode:02X}")
    failed |= not ok

sys.exit(1 if failed else 0)
