"""Utils."""

__all__ = []


def ROL32(X: int, count: int):
    """Rotate left for 32 bit number."""

    count &= 0x1f
    return ((X << count) | (X >> (32 - count))) & 0xffffffff


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_bytes(i: int) -> bytes:
    """Convert integer to minimum number of bytes required to store its value."""

    return i.to_bytes((i.bit_length() + 7) >> 3, "big")
