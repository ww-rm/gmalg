"""Utils."""

import enum

from .errors import *

__all__ = [
    "PADDING_MODE",
    "DataPadder",
]


def ROL32(X: int, count: int):
    """Rotate left for 32 bit number."""

    count &= 0x1f
    return ((X << count) | (X >> (32 - count))) & 0xffffffff


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_bytes(i: int) -> bytes:
    """Convert integer to minimum number of bytes required to store its value."""

    return i.to_bytes((i.bit_length() + 7) >> 3, "big")


class PADDING_MODE(enum.Enum):
    """Block cipher data padding mode.

    Attributes:
        NONE: No padding.
        ZEROS: Append 0x00 bytes until the block size is reached.
        PKCS7: Append N bytes of value N, where N is the number of padding bytes.
        ISO7816_4: Append 0x80, followed by 0x00 bytes until the block size is reached.
        ANSI_X923: Append 0x00 bytes, with the last byte set to the number of padding bytes.
    """

    NONE = enum.auto()
    ZEROS = enum.auto()
    PKCS7 = enum.auto()
    ISO7816_4 = enum.auto()
    ANSI_X923 = enum.auto()


class DataPadder:
    """Data padder used to pad data to a multiple of block size."""

    def __init__(self, block_length: int = 1, method: PADDING_MODE = PADDING_MODE.NONE) -> None:
        """Data padder used to pad data to a multiple of block size.

        Args:
            block_length: Block size in bytes.
            method: Padding method.
        """

        if block_length <= 0:
            raise InvalidArgumentError("block_length must be positive")
        self._block_length = block_length
        self._method = method

    def pad(self, data: bytes) -> bytes:
        """Pad data to a multiple of block size.

        Args:
            data: Input data to be padded.

        Returns:
            bytes: Padded data.
        """

        if self._method is PADDING_MODE.NONE:
            return bytes(data)

        data = bytearray(data)

        rem = len(data) % self._block_length
        pad_len = self._block_length if rem == 0 else self._block_length - rem

        if self._method is PADDING_MODE.ZEROS:
            data.extend([0x00] * pad_len)
        elif self._method is PADDING_MODE.PKCS7:
            data.extend([pad_len] * pad_len)
        elif self._method is PADDING_MODE.ISO7816_4:
            data.append(0x80)
            data.extend([0x00] * (pad_len - 1))
        elif self._method is PADDING_MODE.ANSI_X923:
            data.extend([0x00] * (pad_len - 1))
            data.append(pad_len)
        else:
            raise NotImplementedError(f"Unsupported padding method: {self._method}")
        return bytes(data)

    def unpad(self, data: bytes) -> bytes:
        """Remove padding from data.

        Args:
            data: Padded data.

        Returns:
            bytes: Unpadded data.

        Raises:
            IncorrectLengthError: Invalid padding length.
            CheckFailedError: Invalid padding data.
        """

        if self._method is PADDING_MODE.NONE:
            return bytes(data)

        if not data or len(data) % self._block_length != 0:
            raise IncorrectLengthError("data", f"a multiple of {self._block_length} bytes", f"{len(data)} bytes")

        if self._method is PADDING_MODE.ZEROS:
            data = data.rstrip(b"\x00")
        elif self._method is PADDING_MODE.PKCS7:
            pad_len = data[-1]
            if pad_len == 0 or pad_len > self._block_length:
                raise IncorrectLengthError("PKCS7 last padding byte value", f"positive integer value smaller than {self._block_length}", f"{pad_len}")
            if data[-pad_len:] != bytes([pad_len]) * pad_len:
                raise CheckFailedError("Invalid PKCS7 padding bytes")
            data = data[:-pad_len]
        elif self._method is PADDING_MODE.ISO7816_4:
            # Must end with 0x80 followed by zero or more 0x00
            i = data.rfind(b"\x80")
            if i == -1 or any(b != 0x00 for b in data[i + 1:]):
                raise CheckFailedError("Invalid ISO7816-4 padding")
            data = data[:i]
        elif self._method is PADDING_MODE.ANSI_X923:
            pad_len = data[-1]
            if pad_len == 0 or pad_len > self._block_length:
                raise IncorrectLengthError("ANSI X9.23 last padding byte value", f"positive integer value smaller than {self._block_length}", f"{pad_len}")
            if any(b != 0x00 for b in data[-pad_len:-1]):
                raise CheckFailedError("Invalid ANSI X9.23 padding bytes")
            data = data[:-pad_len]
        else:
            raise NotImplementedError(f"Unsupported padding method: {self._method}")

        return bytes(data)
