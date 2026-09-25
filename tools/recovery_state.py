#!/usr/bin/env python3
from dataclasses import dataclass
from enum import Enum, auto

KNOWN_FW_INFO=bytes.fromhex('01 00 0D 00 20 02 00 00')
SONY_STATED_MIN_FREE=3_000_000
SAFE_MIN_FREE=4*1024*1024  # deliberate safety margin above Sony's ~3 MB requirement

class Action(Enum):
    BLOCK = auto()
    READ_ONLY_DIAG = auto()
    NORMAL_UPDATE_POSSIBLE = auto()
    FAILED_POST_START = auto()
    HARDWARE_RECOVERY_RESEARCH = auto()

@dataclass(frozen=True)
class Snapshot:
    exact_usb: bool
    exact_scsi: bool
    tur_3a00: bool
    capacity_3a00: bool
    fc03_good: bool
    fw_info: bytes
    media_writable: bool=False
    free_bytes: int|None=None
    firmware_verified: bool=False
    metadata_backup_complete: bool=False
    storage_backup_complete: bool=False


def decide(s: Snapshot) -> Action:
    if not (s.exact_usb and s.exact_scsi):
        return Action.BLOCK
    if not (s.fc03_good and s.fw_info==KNOWN_FW_INFO):
        return Action.READ_ONLY_DIAG

    if s.media_writable:
        if s.free_bytes is None or s.free_bytes < SAFE_MIN_FREE:
            return Action.READ_ONLY_DIAG
        if not (s.firmware_verified and s.metadata_backup_complete and s.storage_backup_complete):
            return Action.READ_ONLY_DIAG
        return Action.NORMAL_UPDATE_POSSIBLE

    if s.tur_3a00 and s.capacity_3a00:
        # Issue #1 signature: failed after the original updater had already entered its
        # copy/update-start sequence. Do NOT blindly resend FC/04. With No Media there is
        # currently no verified PC-side path to re-stage MSFWUPGR.UPG.
        return Action.FAILED_POST_START

    return Action.READ_ONLY_DIAG
