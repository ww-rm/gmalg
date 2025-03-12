import os
from typing import List, Optional
import struct

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


class SM4_ECB(SM4):
    """SM4 ECB Mode Algorithm."""

    def __init__(self, key: bytes) -> None:
        """SM4 ECB Mode.

        Args:
            key: 16 bytes key.

        Raises:
            IncorrectLengthError: Incorrect key length.
        """
        super().__init__(key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using SM4 ECB mode.

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
            encrypted_block = super().encrypt(block)
            cipher_text.extend(encrypted_block)

        return bytes(cipher_text)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using SM4 ECB mode.

        Args:
            data: Encrypted data to decrypt. Must be a multiple of the block size.

        Returns:
            bytes: Decrypted data.
        """
        # Decrypt in blocks
        decrypted_data = bytearray()
        for i in range(0, len(data), self.block_length()):
            block = data[i:i + self.block_length()]
            decrypted_block = super().decrypt(block)
            decrypted_data.extend(decrypted_block)

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


class SM4_CFB(SM4):
    """SM4 CFB (Cipher Feedback Mode)."""

    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        """
        Initialize CFB mode.
        :param key: 16-byte encryption key.
        :param iv: 16-byte initialization vector (IV), randomly generated if not provided.
        """
        super().__init__(key)
        if iv and len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes long.")
        self.iv = iv or os.urandom(16)  # Ensure IV exists.

    def pad(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding to ensure data is a multiple of 16 bytes.
        :param data: Input data.
        :return: Padded data.
        """
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    def unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding.
        :param data: Padded input data.
        :return: Unpadded data.
        """
        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid padding detected.")
        return data[:-padding_length]

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt using CFB mode.
        :param plaintext: Data to encrypt.
        :return: IV + encrypted data.
        """
        plaintext = self.pad(plaintext)  # Ensure the length is a multiple of 16 bytes.
        ciphertext = b""
        iv = self.iv  # Initial IV

        for i in range(0, len(plaintext), 16):
            iv_encrypted = self.encrypt_block(iv)  # Encrypt IV to generate keystream.
            encrypted_block = bytes(a ^ b for a, b in zip(iv_encrypted, plaintext[i:i+16]))
            ciphertext += encrypted_block
            iv = encrypted_block  # Use current ciphertext block as IV for next iteration.

        return self.iv + ciphertext  # Prepend IV to ciphertext for proper decryption.

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt using CFB mode.
        :param ciphertext: Data to decrypt (first 16 bytes are IV).
        :return: Decrypted plaintext.
        """
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext must be at least 16 bytes long.")

        iv, ciphertext = ciphertext[:16], ciphertext[16:]  # Extract IV.
        plaintext = b""

        for i in range(0, len(ciphertext), 16):
            iv_encrypted = self.encrypt_block(iv)  # Encrypt IV to generate keystream.
            decrypted_block = bytes(a ^ b for a, b in zip(iv_encrypted, ciphertext[i:i+16]))
            plaintext += decrypted_block
            iv = ciphertext[i:i+16]  # Use current ciphertext block as IV for next iteration.

        return self.unpad(plaintext)  # Remove padding before returning.

    def encrypt_hex(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return the result as a hex string.
        :param plaintext: Plaintext to encrypt (string).
        :return: Hex-encoded ciphertext.
        """
        encrypted_bytes = self.encrypt(plaintext.encode())
        return encrypted_bytes.hex()

    def decrypt_hex(self, ciphertext_hex: str) -> str:
        """
        Decrypt a hex-encoded ciphertext.
        :param ciphertext_hex: Hex string of encrypted data.
        :return: Decrypted plaintext.
        """
        encrypted_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = self.decrypt(encrypted_bytes)
        return decrypted_bytes.decode()

    def display_info(self):
        """Print the current key and IV in hex format."""
        print(f"Key: {self.key.hex()}")
        print(f"IV:  {self.iv.hex()}")

class SM4_OFB(SM4):
    """SM4 OFB (Output Feedback Mode)."""

    def __init__(self, key: bytes, iv: Optional[bytes] = None):
        """
        Initialize OFB mode.
        :param key: 16-byte encryption key.
        :param iv: 16-byte initialization vector (IV), randomly generated if not provided.
        """
        super().__init__(key)
        if iv and len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes long.")
        self.iv = iv or os.urandom(16)  # Ensure IV exists.

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt using OFB mode.
        :param plaintext: Data to encrypt.
        :return: IV + encrypted data.
        """
        ciphertext = b""
        keystream = self.iv  # Initial keystream (IV)

        for i in range(0, len(plaintext), 16):
            keystream = self.encrypt_block(keystream)  # Encrypt the previous keystream.
            block = bytes(a ^ b for a, b in zip(keystream, plaintext[i:i+16]))
            ciphertext += block

        return self.iv + ciphertext  # Prepend IV to ciphertext for decryption.

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt using OFB mode.
        :param ciphertext: Data to decrypt (first 16 bytes are IV).
        :return: Decrypted plaintext.
        """
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext must be at least 16 bytes long.")

        iv, ciphertext = ciphertext[:16], ciphertext[16:]  # Extract IV.
        plaintext = b""
        keystream = iv  # Initial keystream (IV)

        for i in range(0, len(ciphertext), 16):
            keystream = self.encrypt_block(keystream)  # Encrypt the previous keystream.
            block = bytes(a ^ b for a, b in zip(keystream, ciphertext[i:i+16]))
            plaintext += block

        return plaintext  # OFB does not require padding/unpadding.

    def encrypt_hex(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return the result as a hex string.
        :param plaintext: Plaintext to encrypt (string).
        :return: Hex-encoded ciphertext.
        """
        encrypted_bytes = self.encrypt(plaintext.encode())
        return encrypted_bytes.hex()

    def decrypt_hex(self, ciphertext_hex: str) -> str:
        """
        Decrypt a hex-encoded ciphertext.
        :param ciphertext_hex: Hex string of encrypted data.
        :return: Decrypted plaintext.
        """
        encrypted_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = self.decrypt(encrypted_bytes)
        return decrypted_bytes.decode()

    def display_info(self):
        """Print the current key and IV in hex format."""
        print(f"Key: {self.key.hex()}")
        print(f"IV:  {self.iv.hex()}")

class SM4_CTR(SM4):
    """SM4 CTR (Counter Mode)."""

    def __init__(self, key: bytes, nonce: Optional[bytes] = None, counter: int = 0):
        """
        Initialize CTR mode.
        :param key: 16-byte encryption key.
        :param nonce: 8-byte nonce (randomly generated if not provided).
        :param counter: 8-byte initial counter value (default 0).
        """
        super().__init__(key)
        if nonce and len(nonce) != 8:
            raise ValueError("Nonce must be exactly 8 bytes long.")
        self.nonce = nonce or os.urandom(8)  # Generate a random nonce if not provided.
        self.counter = counter  # Initial counter value.

    def _generate_keystream(self, block_index: int) -> bytes:
        """
        Generate a keystream block by encrypting the nonce + counter.
        :param block_index: Block index for counter increment.
        :return: 16-byte keystream block.
        """
        counter_bytes = struct.pack(">Q", self.counter + block_index)  # Convert counter to 8 bytes (big-endian)
        nonce_counter = self.nonce + counter_bytes  # 8-byte nonce + 8-byte counter
        return self.encrypt_block(nonce_counter)  # Encrypt to generate keystream

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt using CTR mode.
        :param plaintext: Data to encrypt.
        :return: Nonce + encrypted data.
        """
        ciphertext = b""
        for i in range(0, len(plaintext), 16):
            keystream = self._generate_keystream(i // 16)  # Generate keystream block
            block = bytes(a ^ b for a, b in zip(keystream, plaintext[i:i+16]))  # XOR with plaintext
            ciphertext += block

        return self.nonce + ciphertext  # Prepend nonce to ciphertext for decryption

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt using CTR mode.
        :param ciphertext: Data to decrypt (first 8 bytes are nonce).
        :return: Decrypted plaintext.
        """
        if len(ciphertext) < 8:
            raise ValueError("Ciphertext must be at least 8 bytes long.")

        nonce, ciphertext = ciphertext[:8], ciphertext[8:]  # Extract nonce.
        plaintext = b""

        for i in range(0, len(ciphertext), 16):
            keystream = self._generate_keystream(i // 16)  # Generate keystream block
            block = bytes(a ^ b for a, b in zip(keystream, ciphertext[i:i+16]))  # XOR with ciphertext
            plaintext += block

        return plaintext  # No need for padding/unpadding in CTR mode.

    def encrypt_hex(self, plaintext: str) -> str:
        """
        Encrypt plaintext and return the result as a hex string.
        :param plaintext: Plaintext to encrypt (string).
        :return: Hex-encoded ciphertext.
        """
        encrypted_bytes = self.encrypt(plaintext.encode())
        return encrypted_bytes.hex()

    def decrypt_hex(self, ciphertext_hex: str) -> str:
        """
        Decrypt a hex-encoded ciphertext.
        :param ciphertext_hex: Hex string of encrypted data.
        :return: Decrypted plaintext.
        """
        encrypted_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = self.decrypt(encrypted_bytes)
        return decrypted_bytes.decode()

    def display_info(self):
        """Print the current key, nonce, and counter in hex format."""
        print(f"Key:    {self.key.hex()}")
        print(f"Nonce:  {self.nonce.hex()}")
        print(f"Counter: {self.counter}")