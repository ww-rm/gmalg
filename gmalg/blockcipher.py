"""Block cipher with working mode."""

import enum

from .base import BlockCipher
from .errors import *

__all__ = [
    "BC_MODE",
    "BlockCipherMode",
    "BlockCipherModeECB",
    "BlockCipherModeCBC",
    "BlockCipherModeCFB",
    "BlockCipherModeOFB",
]


class BC_MODE(enum.Enum):
    """Block cipher working mode.

    Attributes:
        ECB: Electronic Codebook mode.
            Each block is encrypted independently.
            Not secure for most real-world use cases.

        CBC: Cipher Block Chaining mode.
            Each plaintext block is XORed with the previous ciphertext block
            before encryption. Requires an initialization vector (IV).

        CFB: Cipher Feedback mode.
            Turns a block cipher into a self-synchronizing stream cipher.
            Requires an initialization vector (IV).

        OFB: Output Feedback mode.
            Turns a block cipher into a synchronous stream cipher.
            Requires an initialization vector (IV).
    """

    ECB = enum.auto()
    CBC = enum.auto()
    CFB = enum.auto()
    OFB = enum.auto()


class BlockCipherMode:
    """Base class of block cipher with working mode."""

    def __init__(self, bc: BlockCipher) -> None:
        """Base class of block cipher with working mode.

        Args:
            bc (BlockCipher): Block cipher object used in en/decryption.
        """

        self._bc = bc
        self._block_len = bc.block_length()

    def reset(self):
        """Reset internal states."""

        raise NotImplementedError

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt."""

        raise NotImplementedError

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt."""

        raise NotImplementedError


class BlockCipherModeECB(BlockCipherMode):
    """ECB block cipher working mode."""

    def __init__(self, bc: BlockCipher) -> None:
        """ECB block cipher working mode.

        Args:
            bc (BlockCipher): Block cipher object used in en/decryption.
        """

        super().__init__(bc)

    def reset(self):
        """Reset internal states."""

        return

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt.

        Args:
            plain (bytes): Data to be encrypted, must be padded as a multiple of block length.

        Returns:
            cipher: Encrypted plain data.

        Raises:
            IncorrectLengthError: Incorrect plain length.
        """

        plain_len = len(plain)

        if plain_len % self._block_len != 0:
            raise IncorrectLengthError("plain", f"a multiple of {self._block_len} bytes", f"{plain_len} bytes")

        cipher_blocks = []
        for i in range(0, plain_len, self._block_len):
            plain_block = plain[i:i+self._block_len]
            cipher_block = self._bc.encrypt(plain_block)
            cipher_blocks.append(cipher_block)

        return b"".join(cipher_blocks)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt.

        Args:
            cipher (bytes): Data to be decrypted.

        Returns:
            plain: Decrypted data, you may need to remove padding manually.

        Raises:
            IncorrectLengthError: Incorrect cipher length.
        """

        cipher_len = len(cipher)

        if cipher_len % self._block_len != 0:
            raise IncorrectLengthError("cipher", f"a multiple of {self._block_len} bytes", f"{cipher_len} bytes")

        plain_blocks = []
        for i in range(0, cipher_len, self._block_len):
            cipher_block = cipher[i:i+self._block_len]
            plain_block = self._bc.decrypt(cipher_block)
            plain_blocks.append(plain_block)

        return b"".join(plain_blocks)


class BlockCipherModeCBC(BlockCipherMode):
    """CBC block cipher working mode."""

    def __init__(self, bc: BlockCipher, iv: bytes) -> None:
        """CBC block cipher working mode.

        Args:
            bc (BlockCipher): Block cipher object used in en/decryption.
            iv (bytes): Initial vector, must be the same length as block length.

        Raises:
            IncorrectLengthError: Incorrect iv length.
        """

        super().__init__(bc)

        if len(iv) != bc.block_length():
            raise IncorrectLengthError("IV", f"{bc.block_length()} bytes", f"{len(iv)} bytes")

        self._iv = bytes(iv)
        self._last_cipher_block = self._iv

    def reset(self):
        """Reset internal states."""

        self._last_cipher_block = self._iv

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt.

        Args:
            plain (bytes): Data to be encrypted, must be padded as a multiple of block length.

        Returns:
            cipher: Encrypted plain data.

        Raises:
            IncorrectLengthError: Incorrect plain length.
        """

        plain_len = len(plain)

        if plain_len % self._block_len != 0:
            raise IncorrectLengthError("plain", f"a multiple of {self._block_len} bytes", f"{plain_len} bytes")

        cipher_blocks = []
        for i in range(0, plain_len, self._block_len):
            plain_block = plain[i:i+self._block_len]
            xor_block = bytes(b1 ^ b2 for b1, b2 in zip(self._last_cipher_block, plain_block))
            cipher_block = self._bc.encrypt(xor_block)
            cipher_blocks.append(cipher_block)
            self._last_cipher_block = cipher_block

        return b"".join(cipher_blocks)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt.

        Args:
            cipher (bytes): Data to be decrypted.

        Returns:
            plain: Decrypted data, you may need to remove padding manually.

        Raises:
            IncorrectLengthError: Incorrect cipher length.
        """

        cipher_len = len(cipher)

        if cipher_len % self._block_len != 0:
            raise IncorrectLengthError("cipher", f"a multiple of {self._block_len} bytes", f"{cipher_len} bytes")

        plain_blocks = []
        for i in range(0, cipher_len, self._block_len):
            cipher_block = cipher[i:i+self._block_len]
            xor_block = self._bc.decrypt(cipher_block)
            plain_block = bytes(b1 ^ b2 for b1, b2 in zip(self._last_cipher_block, xor_block))
            plain_blocks.append(plain_block)
            self._last_cipher_block = bytes(cipher_block)

        return b"".join(plain_blocks)


class BlockCipherModeCFB(BlockCipherMode):
    """CFB block cipher working mode."""

    def __init__(self, bc: BlockCipher, iv: bytes, segment_length: int = 1) -> None:
        """CFB block cipher working mode.

        Args:
            bc (BlockCipher): Block cipher object used in en/decryption.
            iv (bytes): Initial vector, must be the same length as block length.
            segment_length (int): Segment length of data stream in bytes,
                must be little or equal than block length, default to 1 (per-byte).

        Raises:
            IncorrectLengthError: Incorrect iv length.
            InvalidArgumentError: Invalid segment length.
        """

        super().__init__(bc)

        if len(iv) != bc.block_length():
            raise IncorrectLengthError("iv", f"{bc.block_length()} bytes", f"{len(iv)} bytes")

        if segment_length > bc.block_length():
            raise InvalidArgumentError(f"segment length ({segment_length}) can't be greater than block length ({bc.block_length()}).")

        self._iv = bytes(iv)
        self._segment_len = segment_length
        self._shift_register = self._iv
        self._key_stream = self._bc.encrypt(self._shift_register)[:self._segment_len]
        self._init_key_stream = self._key_stream

    def reset(self):
        """Reset internal states."""

        self._shift_register = self._iv
        self._key_stream = self._init_key_stream

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt.

        Args:
            plain (bytes): Data to be encrypted, no need to be padded.

        Returns:
            cipher: Encrypted plain data.
        """

        if len(plain) <= 0:
            return b""

        cipher_head = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain))
        head_len = len(cipher_head)
        self._shift_register = self._shift_register[head_len:] + cipher_head
        self._key_stream = self._key_stream[head_len:]

        if len(self._key_stream) > 0:
            return cipher_head

        self._key_stream = self._bc.encrypt(self._shift_register)[:self._segment_len]

        plain = plain[head_len:]
        plain_len = len(plain)
        if plain_len <= 0:
            return cipher_head

        tail_len = plain_len % self._segment_len
        plain_segments_len = plain_len - tail_len

        cipher_segments = [cipher_head]
        for i in range(0, plain_segments_len, self._segment_len):
            plain_segment = plain[i:i+self._segment_len]
            cipher_segment = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain_segment))
            cipher_segments.append(cipher_segment)
            self._shift_register = self._shift_register[self._segment_len:] + cipher_segment
            self._key_stream = self._bc.encrypt(self._shift_register)[:self._segment_len]

        if tail_len > 0:
            plain_tail = plain[plain_segments_len:]
            cipher_tail = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain_tail))
            cipher_segments.append(cipher_tail)
            self._shift_register = self._shift_register[tail_len:] + cipher_tail
            self._key_stream = self._key_stream[tail_len:]

        return b"".join(cipher_segments)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt.

        Args:
            cipher (bytes): Data to be decrypted.

        Returns:
            plain: Decrypted data, you may need to remove padding manually.
        """

        if len(cipher) <= 0:
            return b""

        plain_head = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher))
        head_len = len(plain_head)
        self._shift_register = self._shift_register[head_len:] + cipher[:head_len]
        self._key_stream = self._key_stream[head_len:]

        if len(self._key_stream) > 0:
            return plain_head

        self._key_stream = self._bc.encrypt(self._shift_register)[:self._segment_len]

        cipher = cipher[head_len:]
        cipher_len = len(cipher)
        if cipher_len <= 0:
            return plain_head

        tail_len = cipher_len % self._segment_len
        cipher_segments_len = cipher_len - tail_len

        plain_segments = [plain_head]
        for i in range(0, cipher_segments_len, self._segment_len):
            cipher_segment = cipher[i:i+self._segment_len]
            plain_segment = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher_segment))
            plain_segments.append(plain_segment)
            self._shift_register = self._shift_register[self._segment_len:] + cipher_segment
            self._key_stream = self._bc.encrypt(self._shift_register)[:self._segment_len]

        if tail_len > 0:
            cipher_tail = cipher[cipher_segments_len:]
            plain_tail = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher_tail))
            plain_segments.append(plain_tail)
            self._shift_register = self._shift_register[tail_len:] + cipher_tail
            self._key_stream = self._key_stream[tail_len:]

        return b"".join(plain_segments)


class BlockCipherModeOFB(BlockCipherMode):
    """OFB block cipher working mode."""

    def __init__(self, bc: BlockCipher, iv: bytes) -> None:
        """OFB block cipher working mode.

        Args:
            bc (BlockCipher): Block cipher object used in en/decryption.
            iv (bytes): Initial vector, must be the same length as block length.

        Raises:
            IncorrectLengthError: Incorrect iv length.
        """

        super().__init__(bc)

        if len(iv) != bc.block_length():
            raise IncorrectLengthError("iv", f"{bc.block_length()} bytes", f"{len(iv)} bytes")

        self._key_stream = self._bc.encrypt(iv)
        self._next_key_block_in = self._key_stream
        self._init_key_stream = self._key_stream

    def reset(self):
        """Reset internal states."""

        self._key_stream = self._init_key_stream
        self._next_key_block_in = self._key_stream

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt.

        Args:
            plain (bytes): Data to be encrypted, no need to be padded.

        Returns:
            cipher: Encrypted plain data.
        """

        if len(plain) <= 0:
            return b""

        cipher_head = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain))
        head_len = len(cipher_head)
        self._key_stream = self._key_stream[head_len:]

        if len(self._key_stream) > 0:
            return cipher_head

        self._key_stream = self._bc.encrypt(self._next_key_block_in)
        self._next_key_block_in = self._key_stream

        plain = plain[head_len:]
        plain_len = len(plain)
        if plain_len <= 0:
            return cipher_head

        tail_len = plain_len % self._block_len
        plain_blocks_len = plain_len - tail_len

        cipher_blocks = [cipher_head]
        for i in range(0, plain_blocks_len, self._block_len):
            plain_block = plain[i:i+self._block_len]
            cipher_block = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain_block))
            cipher_blocks.append(cipher_block)
            self._key_stream = self._bc.encrypt(self._next_key_block_in)
            self._next_key_block_in = self._key_stream

        if tail_len > 0:
            plain_tail = plain[plain_blocks_len:]
            cipher_tail = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, plain_tail))
            cipher_blocks.append(cipher_tail)
            self._key_stream = self._key_stream[tail_len:]

        return b"".join(cipher_blocks)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt.

        Args:
            cipher (bytes): Data to be decrypted.

        Returns:
            plain: Decrypted data, you may need to remove padding manually.
        """

        if len(cipher) <= 0:
            return b""

        plain_head = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher))
        head_len = len(plain_head)
        self._key_stream = self._key_stream[head_len:]

        if len(self._key_stream) > 0:
            return plain_head

        self._key_stream = self._bc.encrypt(self._next_key_block_in)
        self._next_key_block_in = self._key_stream

        cipher = cipher[head_len:]
        cipher_len = len(cipher)
        if cipher_len <= 0:
            return plain_head

        tail_len = cipher_len % self._block_len
        cipher_blocks_len = cipher_len - tail_len

        plain_blocks = [plain_head]
        for i in range(0, cipher_blocks_len, self._block_len):
            cipher_block = cipher[i:i+self._block_len]
            plain_block = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher_block))
            plain_blocks.append(plain_block)
            self._key_stream = self._bc.encrypt(self._next_key_block_in)
            self._next_key_block_in = self._key_stream

        if tail_len > 0:
            cipher_tail = cipher[cipher_blocks_len:]
            plain_tail = bytes(b1 ^ b2 for b1, b2 in zip(self._key_stream, cipher_tail))
            plain_blocks.append(plain_tail)
            self._key_stream = self._key_stream[tail_len:]

        return b"".join(plain_blocks)
