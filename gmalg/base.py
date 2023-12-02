"""Base abstract classes."""

from typing import Callable, Type

from . import errors

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


class SMCoreBase:
    """SM Core base."""

    def __init__(self, hash_cls: Type[Hash], rnd_fn: Callable[[int], int]) -> None:
        """SM Core Base.

        Args:
            hash_fn (Hash): hash function used in cipher.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.
        """

        self._hash_cls = hash_cls
        self._rnd_fn = rnd_fn

    def _hash_fn(self, data: bytes) -> bytes:
        hash_obj = self._hash_cls()
        hash_obj.update(data)
        return hash_obj.value()

    def _randint(self, a: int, b: int) -> int:
        bitlength = b.bit_length()
        while True:
            n = self._rnd_fn(bitlength)
            if n < a or n > b:
                continue
            return n

    def key_derivation_fn(self, Z: bytes, klen: int) -> bytes:
        """KDF

        Args:
            Z (bytes): secret bytes.
            klen (int): key byte length

        Raises:
            DataOverflowError: klen is too large.
        """

        hash_fn = self._hash_fn
        v = self._hash_cls.hash_length()

        count, tail = divmod(klen, v)
        if count + (tail > 0) > 0xffffffff:
            raise errors.DataOverflowError("Key stream", f"{0xffffffff * v} bytes")

        K = bytearray()
        for ct in range(1, count + 1):
            K.extend(hash_fn(Z + ct.to_bytes(4, "big")))

        if tail > 0:
            K.extend(hash_fn(Z + (count + 1).to_bytes(4, "big"))[:tail])

        return bytes(K)
