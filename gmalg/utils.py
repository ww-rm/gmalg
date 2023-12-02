from typing import Tuple

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


def inverse(x: int, p: int):
    """Modular inverse of p."""

    r1 = p
    r2 = x
    t1 = 0
    t2 = 1
    while r2 > 0:
        q, r = divmod(r1, r2)
        r1 = r2
        r2 = r
        t = t1 - q * t2
        t1 = t2
        t2 = t
    return t1 % p
