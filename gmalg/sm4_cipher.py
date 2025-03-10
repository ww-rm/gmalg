from typing import List, Optional

from .errors import *
from .sm4 import SM4


class SM4_CBC(SM4):
    """SM4 CBC Mode Algorithm."""

    def __init__(self, key: bytes, iv: Optional[bytes] = None) -> None:
        """SM4 CBC Mode.

        Args:
            key: 16 bytes key.
            iv: 16 bytes initialization vector (IV), defaults to random if None.

        Raises:
            IncorrectLengthError: Incorrect key or IV length.
        """
        super().__init__(key)

        if iv is None:
            # Generate a random IV if not provided
            self._iv = os.urandom(self.block_length())
        else:
            if len(iv) != self.block_length():
                raise IncorrectLengthError(
                    "IV", f"{self.block_length()} bytes", f"{len(iv)} bytes")
            self._iv = iv

        self._previous_cipher_block = self._iv

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using SM4 CBC mode.

        Args:
            data: Data to encrypt. Must be a multiple of the block size.

        Returns:
            bytes: Encrypted data.
        """
        # Pad the data to make it a multiple of the block size (16 bytes)
        data = self._pad(data)

        cipher_text = bytearray()
        # Process each 16-byte block
        for i in range(0, len(data), self.block_length()):
            block = data[i:i + self.block_length()]
            # XOR with the previous cipher block (for CBC mode)
            block = bytes(a ^ b for a, b in zip(
                block, self._previous_cipher_block))
            encrypted_block = super().encrypt(block)
            cipher_text.extend(encrypted_block)

            # Update the previous cipher block to the current encrypted block
            self._previous_cipher_block = encrypted_block

        return bytes(cipher_text)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using SM4 CBC mode.

        Args:
            data: Encrypted data to decrypt. Must be a multiple of the block size.

        Returns:
            bytes: Decrypted data.
        """
        # Decrypt in blocks and remove padding
        decrypted_data = bytearray()
        for i in range(0, len(data), self.block_length()):
            block = data[i:i + self.block_length()]
            decrypted_block = super().decrypt(block)

            # XOR with the previous cipher block to get the original plaintext
            decrypted_block = bytes(a ^ b for a, b in zip(
                decrypted_block, self._previous_cipher_block))
            decrypted_data.extend(decrypted_block)

            # Update the previous cipher block to the current encrypted block
            self._previous_cipher_block = block

        # Remove padding
        return self._unpad(decrypted_data)

    def _pad(self, data: bytes) -> bytes:
        """Pad data to a multiple of the block size (16 bytes)."""
        padding_length = self.block_length() - len(data) % self.block_length()
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        """Remove padding from decrypted data."""
        padding_length = data[-1]
        return data[:-padding_length]
