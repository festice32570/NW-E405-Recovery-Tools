#!/usr/bin/env python3
"""Static specification for Sony FrankPACAPI ATRACAD2 device-mode query.

No hardware access.  The raw 0x404-byte response is privacy-sensitive/unknown;
public summaries intentionally expose only transport status, SHA-256, and the
single mode bit that Sony itself consumes for behavior selection.
"""
from dataclasses import dataclass
import hashlib

CDB = bytes.fromhex('A4 00 00 00 00 00 00 BC 04 04 33 00')
RESPONSE_LEN = 0x404
MODE_OFFSET = 0x0C
MODE_MASK = 0x80


def build_cdb() -> bytes:
    return CDB


def mode_bit(response: bytes) -> int:
    if len(response) != RESPONSE_LEN:
        raise ValueError('A4/BC/33 response must be exactly 0x404 bytes')
    return (response[MODE_OFFSET] >> 7) & 1


def sony_behavior_type(response: bytes) -> int:
    # Direct caller around 0x6c13664f maps mode 0 -> 2, mode 1 -> 4.
    return 4 if mode_bit(response) else 2


def safe_summary(response: bytes) -> dict[str, int | str]:
    if len(response) != RESPONSE_LEN:
        raise ValueError('A4/BC/33 response must be exactly 0x404 bytes')
    return {
        'length': len(response),
        'sha256': hashlib.sha256(response).hexdigest(),
        'mode_bit': mode_bit(response),
        'sony_behavior_type': sony_behavior_type(response),
    }

if __name__ == '__main__':
    print(build_cdb().hex(' ').upper(), f'DATA-IN {RESPONSE_LEN} bytes')
