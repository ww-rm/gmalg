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


def generate_lucas(X: int, Y: int, k: int, p: int) -> Tuple[int, int]:
    """Lucas Sequence, k begin at 0.

    Uk = X * Uk-1 - Y * Uk-2
    Vk = X * Vk-1 - Y * Vk-2

    Returns:
        (int, int): The k-th lucas value pair.
    """

    delta = (X * X - 4 * Y) % p
    inv2 = inverse(2, p)

    U, V = 0, 2
    for i in f"{k:b}":
        U, V = (U * V) % p, ((V * V + delta * U * U) * inv2) % p
        if i == "1":
            U, V = ((X * U + V) * inv2) % p, ((X * V + delta * U) * inv2) % p

    return U, V


def sqrt_4u3(x: int, p: int, u: int):
    """sqrt_8u3 and sqrt_8u7"""

    y = pow(x, u + 1, p)
    if (y * y) % p == x:
        return y
    return -1


def sqrt_8u5(x: int, p: int, u: int):
    z = pow(x, 2 * u + 1, p)
    if z == 1:
        return pow(x, u + 1, p)
    if z == p - 1:
        return (2 * x * pow(4 * x, u, p)) % p
    return -1


def sqrt_8u1(x: int, p: int, u: int):
    _4u1 = 4 * u + 1
    p_1 = p - 1
    Y = x
    for X in range(1, p):
        U, V = generate_lucas(X, Y, _4u1, p)

        if (V * V - 4 * Y) % p == 0:
            return (V * inverse(2, p)) % p

        if U != 1 or U != p_1:
            return -1

    return -1
