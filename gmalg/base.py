"""Base abstract classes."""

__all__ = [
    "Hash",
    "BlockCipher",
]


class Hash:
    @classmethod
    def max_msg_length(self) -> int:
        """Get maximum message length in bytes."""

        raise NotImplementedError

    @classmethod
    def hash_length(self) -> int:
        """Get output hash value length in bytes."""

        raise NotImplementedError

    def __init__(self) -> None:
        raise NotImplementedError

    def update(self, data: bytes) -> None:
        """Update internal state.

        Args:
            data (bytes): data stream to be updated.
        """

        raise NotImplementedError

    def value(self) -> bytes:
        """Returns current hash value in bytes.

        Returns:
            bytes: Hash value.
        """

        raise NotImplementedError


class BlockCipher:
    @classmethod
    def key_length(self) -> int:
        """Get key length in bytes."""

        raise NotImplementedError

    @classmethod
    def block_length(self) -> int:
        """Get block length in bytes."""

        raise NotImplementedError

    def __init__(self, key: bytes) -> None:
        """Block Cipher

        Args:
            key (bytes): key used in cipher, has a length of `BlockCipher.key_length()`
        """

        raise NotImplementedError

    def encrypt(self, block: bytes) -> bytes:
        """Encrypt"""

        raise NotImplementedError

    def decrypt(self, block: bytes) -> bytes:
        """Decrypt"""

        raise NotImplementedError
