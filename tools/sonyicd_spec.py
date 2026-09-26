#!/usr/bin/env python3
"""Static SONYICD command specification recovered from Sony IcdMSCom.dll.

This module only builds/decodes byte strings.  It performs no device I/O.
Live use must remain separately gated in the recovery tool.
"""
from dataclasses import dataclass

PREFIX = b'\xFC\x00'
SIGNATURE = b'SONYICD'
CDB_LEN = 12

@dataclass(frozen=True)
class SonyIcdCommand:
    name: str
    command: int
    transfer: str       # 'in', 'out', 'none'
    length: int
    privacy: str

COMMANDS = {
    0x01: SonyIcdCommand('GetTargetIdentifier', 0x01, 'in',   0x74,  'private-raw'),
    0x02: SonyIcdCommand('GetPreferenceInfo',   0x02, 'in',   0x48,  'private-raw'),
    0x04: SonyIcdCommand('GetRevokeListST-0',   0x04, 'in',   0x1F8, 'private-raw'),
    0x05: SonyIcdCommand('GetRevokeListST-1',   0x05, 'in',   0x1F8, 'private-raw'),
    0x41: SonyIcdCommand('SetUserNameDevice',    0x41, 'out',  0,     'destructive'),
    0x42: SonyIcdCommand('SetPreferenceMenu',    0x42, 'out',  0,     'destructive'),
    0x43: SonyIcdCommand('SetUniqueID',           0x43, 'out',  0,     'destructive'),
    0x44: SonyIcdCommand('SetRevokeListST-0',     0x44, 'out',  0,     'destructive'),
    0x45: SonyIcdCommand('SetRevokeListST-1',     0x45, 'out',  0,     'destructive'),
    0x80: SonyIcdCommand('Reset',                 0x80, 'none', 0,     'state-changing'),
}

READ_ONLY_PROBE_COMMANDS = (0x01, 0x02)


def build_cdb(command: int, length: int | None = None) -> bytes:
    if not (0 <= command <= 0xFF):
        raise ValueError('command out of range')
    spec = COMMANDS.get(command)
    if length is None:
        if spec is None:
            raise ValueError('length required for unknown command')
        length = spec.length
    if not (0 <= length <= 0xFFFF):
        raise ValueError('length out of range')
    return PREFIX + bytes([command]) + SIGNATURE + length.to_bytes(2, 'big')


def transfer_family(command: int) -> str:
    family = command & 0xC0
    return {0x00: 'in', 0x40: 'out', 0x80: 'none'}.get(family, 'unsupported')


def target_identifier_status(response: bytes) -> int:
    if len(response) != 0x74:
        raise ValueError('GetTargetIdentifier response must be exactly 0x74 bytes')
    return response[0x0F]


def target_identifier_safe_summary(response: bytes) -> dict[str, int | str]:
    """Return only non-raw metadata suitable for internal analysis.

    The two strings and opaque identifier fields are intentionally not returned.
    Raw response must remain private until every field is understood.
    """
    if len(response) != 0x74:
        raise ValueError('GetTargetIdentifier response must be exactly 0x74 bytes')
    import hashlib
    return {
        'status': response[0x0F],
        'length': len(response),
        'sha256': hashlib.sha256(response).hexdigest(),
    }


if __name__ == '__main__':
    for cmd in READ_ONLY_PROBE_COMMANDS:
        spec = COMMANDS[cmd]
        print(f'{spec.name}: {build_cdb(cmd).hex(" ").upper()} DATA-{spec.transfer.upper()} 0x{spec.length:X}')
