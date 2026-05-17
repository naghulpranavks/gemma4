"""
LoRa Payload Encoder/Decoder — Compact Binary Format

Packs threat alerts into a minimal 20-byte binary payload
for ultra-low-bandwidth LoRaWAN transmission.

Payload structure (little-endian, 20 bytes):
  Byte 0:     msg_type      (uint8)  — 0x01=alert, 0x02=heartbeat, 0x03=battery
  Byte 1:     threat_class  (uint8)  — 0x01=chainsaw, 0x02=gunshot, 0x03=vehicle
  Byte 2:     confidence    (uint8)  — 0-100 percentage
  Bytes 3-6:  latitude      (int32)  — microdegrees (lat × 1,000,000)
  Bytes 7-10: longitude     (int32)  — microdegrees (lon × 1,000,000)
  Bytes 11-14: timestamp    (uint32) — Unix epoch seconds
  Byte 15:    battery_pct   (uint8)  — 0-100 percentage
  Byte 16:    node_id       (uint8)  — sentinel node identifier
  Byte 17:    audio_db      (uint8)  — peak audio amplitude dB
  Byte 18:    temp_c        (uint8)  — CPU temperature °C
  Byte 19:    flags         (uint8)  — bitfield
"""

import struct
import time
import logging
from dataclasses import dataclass
from enum import IntEnum

logger = logging.getLogger(__name__)

# Binary format: little-endian, 20 bytes total
_PAYLOAD_FORMAT = "<BBBiiIBBBBB"
_PAYLOAD_SIZE = struct.calcsize(_PAYLOAD_FORMAT)  # 20 bytes

assert _PAYLOAD_SIZE == 20, f"Payload must be 20 bytes, got {_PAYLOAD_SIZE}"


class MsgType(IntEnum):
    ALERT = 0x01
    HEARTBEAT = 0x02
    BATTERY = 0x03


class ThreatCode(IntEnum):
    UNKNOWN = 0x00
    CHAINSAW = 0x01
    GUNSHOT = 0x02
    VEHICLE = 0x03
    AMBIENT = 0x04
    EXPLOSION = 0x05
    TRAP_SNAP = 0x06
    DRONE = 0x07
    DOG_BARK = 0x08
    AXE = 0x09
    POACHER = 0x0A


class PayloadFlags:
    """Bitfield flags for byte 19."""
    GPS_VALID = 0x01       # bit 0
    SOLAR_CHARGING = 0x02  # bit 1
    BUFFER_OVERFLOW = 0x04 # bit 2

    @staticmethod
    def encode(gps_valid=False, solar_charging=False, buffer_overflow=False):
        flags = 0
        if gps_valid:
            flags |= PayloadFlags.GPS_VALID
        if solar_charging:
            flags |= PayloadFlags.SOLAR_CHARGING
        if buffer_overflow:
            flags |= PayloadFlags.BUFFER_OVERFLOW
        return flags

    @staticmethod
    def decode(flags_byte):
        return {
            "gps_valid": bool(flags_byte & PayloadFlags.GPS_VALID),
            "solar_charging": bool(flags_byte & PayloadFlags.SOLAR_CHARGING),
            "buffer_overflow": bool(flags_byte & PayloadFlags.BUFFER_OVERFLOW),
        }


@dataclass
class AlertPayload:
    """Structured representation of a LoRa alert payload."""
    msg_type: int
    threat_class: int
    confidence: int
    latitude_udeg: int
    longitude_udeg: int
    timestamp: int
    battery_pct: int
    node_id: int
    audio_db: int
    temp_c: int
    flags: int

    @property
    def latitude(self) -> float:
        return self.latitude_udeg / 1_000_000

    @property
    def longitude(self) -> float:
        return self.longitude_udeg / 1_000_000

    @property
    def threat_name(self) -> str:
        names = {
            0x00: "UNKNOWN", 0x01: "CHAINSAW",
            0x02: "GUNSHOT", 0x03: "VEHICLE", 0x04: "AMBIENT",
            0x05: "EXPLOSION", 0x06: "TRAP_SNAP",
            0x07: "DRONE", 0x08: "DOG_BARK", 0x09: "AXE",
            0x0A: "POACHER",
        }
        return names.get(self.threat_class, "UNKNOWN")

    @property
    def flags_decoded(self) -> dict:
        return PayloadFlags.decode(self.flags)


def encode_alert(
    threat_class: int,
    confidence_pct: int,
    lat_udeg: int = 0,
    lon_udeg: int = 0,
    node_id: int = 1,
    audio_db: int = 0,
    temp_c: int = 0,
    battery_pct: int = 100,
    flags: int = 0,
) -> bytes:
    """
    Encode a threat alert into a 20-byte binary payload.

    Returns:
        20 bytes of packed binary data.
    """
    return struct.pack(
        _PAYLOAD_FORMAT,
        MsgType.ALERT,
        threat_class,
        min(100, max(0, confidence_pct)),
        lat_udeg,
        lon_udeg,
        int(time.time()),
        min(100, max(0, battery_pct)),
        node_id,
        min(255, max(0, audio_db)),
        min(255, max(0, temp_c)),
        flags,
    )


def encode_heartbeat(
    node_id: int = 1,
    battery_pct: int = 100,
    temp_c: int = 0,
    lat_udeg: int = 0,
    lon_udeg: int = 0,
    flags: int = 0,
) -> bytes:
    """Encode a heartbeat status payload (20 bytes)."""
    return struct.pack(
        _PAYLOAD_FORMAT,
        MsgType.HEARTBEAT,
        ThreatCode.AMBIENT,
        0,  # no confidence for heartbeat
        lat_udeg,
        lon_udeg,
        int(time.time()),
        min(100, max(0, battery_pct)),
        node_id,
        0,
        min(255, max(0, temp_c)),
        flags,
    )


def decode_payload(data: bytes) -> AlertPayload:
    """
    Decode a 20-byte binary payload into an AlertPayload.

    Args:
        data: Exactly 20 bytes of binary payload.

    Returns:
        AlertPayload dataclass.

    Raises:
        ValueError: If data is not exactly 20 bytes.
    """
    if len(data) != _PAYLOAD_SIZE:
        raise ValueError(
            f"Payload must be {_PAYLOAD_SIZE} bytes, got {len(data)}"
        )

    fields = struct.unpack(_PAYLOAD_FORMAT, data)
    return AlertPayload(*fields)


def to_hex_string(data: bytes) -> str:
    """Convert binary payload to hex string for AT+SEND commands."""
    return data.hex().upper()


def from_hex_string(hex_str: str) -> bytes:
    """Convert hex string back to binary payload."""
    return bytes.fromhex(hex_str)
