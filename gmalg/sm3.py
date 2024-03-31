"""SM3 Algorithm Implementation Module."""

from typing import List

from .base import Hash
from .errors import *
from .utils import ROL32

__all__ = ["SM3"]

_ROL_T_TABLE = [
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
]


def _precomp_rol_table():
    return [ROL32(_T(i), i) for i in range(64)]


def _T(i):
    return 0x79cc4519 if i <= 15 else 0x7a879d8a


def _FF(i, X, Y, Z):
    return (X ^ Y ^ Z) if i <= 15 else ((X & Y) | (X & Z) | (Y & Z))


def _GG(i, X, Y, Z):
    return (X ^ Y ^ Z) if i <= 15 else ((X & Y) | (~X & Z))


def _P0(X):
    return X ^ ROL32(X, 9) ^ ROL32(X, 17)


def _P1(X):
    return X ^ ROL32(X, 15) ^ ROL32(X, 23)


def _expand(B: bytes, W1: List[int], W2: List[int]):
    """Expand message block."""

    for i in range(16):
        W1[i] = int.from_bytes(B[i * 4:i * 4 + 4], "big")
    for i in range(16, 68):
        W1[i] = _P1(W1[i - 16] ^ W1[i - 9] ^ ROL32(W1[i - 3], 15)) ^ ROL32(W1[i - 13], 7) ^ W1[i - 6]
    for i in range(64):
        W2[i] = W1[i] ^ W1[i + 4]


def _compress(W1: List[int], W2: List[int], V: List[int]):
    """Compress words."""

    A, B, C, D, E, F, G, H = V

    for i in range(64):
        SS1 = ROL32((ROL32(A, 12) + E + _ROL_T_TABLE[i]) & 0xffffffff, 7)
        SS2 = SS1 ^ ROL32(A, 12)
        TT1 = (_FF(i, A, B, C) + D + SS2 + W2[i]) & 0xffffffff
        TT2 = (_GG(i, E, F, G) + H + SS1 + W1[i]) & 0xffffffff
        D = C
        C = ROL32(B, 9)
        B = A
        A = TT1
        H = G
        G = ROL32(F, 19)
        F = E
        E = _P0(TT2)

    V[0] ^= A
    V[1] ^= B
    V[2] ^= C
    V[3] ^= D
    V[4] ^= E
    V[5] ^= F
    V[6] ^= G
    V[7] ^= H


class SM3(Hash):
    """SM3 Algorithm."""

    @classmethod
    def max_msg_length(self) -> int:
        """Get maximum message length in bytes."""

        return 0x1fffffffffffffff  # (1 << 64 - 1) >> 3

    @classmethod
    def hash_length(self) -> int:
        """Get output hash value length in bytes."""

        return 32

    def __init__(self) -> None:
        """SM3 Algorithm."""

        self._value: List[int] = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
        self._msg_len: int = 0
        self._msg_block_buffer: bytearray = bytearray()

        self._words_buffer1: List[int] = [0] * 68
        self._words_buffer2: List[int] = [0] * 64

    def update(self, data: bytes) -> None:
        """Update internal state.

        Args:
            data: Data stream to be updated.

        Raises:
            DataOverflowError: Message too long.
        """

        if self._msg_len + len(data) > self.max_msg_length():
            raise DataOverflowError("Message", f"0x{self.max_msg_length():x} bytes")

        B = self._msg_block_buffer
        W1 = self._words_buffer1
        W2 = self._words_buffer2
        V = self._value

        b_len = len(B)
        d_len = len(data)
        if b_len + d_len >= 64:
            # process last short block
            begin = 64 - b_len
            B.extend(data[:begin])
            _expand(B, W1, W2)
            _compress(W1, W2, V)
            B.clear()

            pos = begin
            while pos + 63 < d_len:
                _expand(data[pos:pos+64], W1, W2)
                _compress(W1, W2, V)
                pos += 64

            B.extend(data[pos:])
        else:
            B.extend(data)

        self._msg_len += d_len

    def value(self) -> bytes:
        """Get current hash value.

        Returns:
            bytes: Current hash value.

        Note:
            Each invocation of the method will dynamically compute the hash value that should be output,
                so it is advisable to retain the resulting hash value after the method call.
        """

        B = self._msg_block_buffer.copy()
        W1 = self._words_buffer1
        W2 = self._words_buffer2
        V = self._value.copy()

        b_len = len(B)

        B.append(0x80)

        if b_len < 56:
            for _ in range(b_len + 1, 56):
                B.append(0x00)
        else:
            for _ in range(b_len + 1, 64):
                B.append(0x00)
            _expand(B, W1, W2)
            _compress(W1, W2, V)
            B = bytearray(56)

        B.extend((self._msg_len << 3).to_bytes(8, "big"))

        _expand(B, W1, W2)
        _compress(W1, W2, V)

        value = bytearray()
        for w in V:
            value.extend(w.to_bytes(4, "big"))
        return bytes(value)
