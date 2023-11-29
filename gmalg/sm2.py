import enum
import secrets
from typing import Callable, Tuple

from . import errors
from .core import ECDLP, EllipticCurveCipher
from .sm3 import SM3

__all__ = [
    "SM2",
    "PC_MODE",
    "KEYXCHG_MODE",
]


def _btoi(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _itob(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) >> 3, "big")


_ecdlp = ECDLP(
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC,
    0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93,
    0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7,
    0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123,
)


class PC_MODE(enum.Enum):
    RAW = enum.auto()
    COMPRESS = enum.auto()
    MIXED = enum.auto()


class KEYXCHG_MODE(enum.Enum):
    INITIATOR = enum.auto()
    RESPONDER = enum.auto()


class SM2:
    """SM2"""

    def __init__(self, d: bytes = None, id_: bytes = None, P: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW) -> None:
        """SM2.

        Args:
            d (bytes): secret key.
            P (bytes): public key (point).
            id_ (bytes): user id used in sign.

            rnd_fn ((int) -> int): random function used to generate k-bit random number, default to `secrets.randbits`
            pc_mode (PC_MODE): pc_mode used for generated data, no effects on the data to be parsed.
        """

        self._ecc = EllipticCurveCipher(_ecdlp, SM3, rnd_fn or self._default_rnd_fn)
        self._d = _btoi(d) if d else None

        if P:
            self._xP, self._yP = self.bytes_to_point(P)
        else:
            if self._d:
                self._xP, self._yP = self._ecc.get_pubkey(self._d)  # try generate public key
            else:
                self._xP, self._yP = None, None

        self._id = id_
        self._pc_mode = pc_mode

    def _default_rnd_fn(self, k: int) -> int:
        return secrets.randbits(k)

    def point_to_bytes(self, x: int, y: int, mode: PC_MODE) -> bytes:
        """Convert point to bytes."""

        ecdlp = self._ecc.ecdlp

        if ecdlp.isinf(x, y):
            return b"\x00"

        if mode is PC_MODE.RAW:
            return b"\x04" + ecdlp.itob(x) + ecdlp.itob(y)
        elif mode is PC_MODE.COMPRESS:
            if y & 0x1:
                return b"\x03" + ecdlp.itob(x)
            else:
                return b"\x02" + ecdlp.itob(x)
        elif mode is PC_MODE.MIXED:
            if y & 0x1:
                return b"\x07" + ecdlp.itob(x) + ecdlp.itob(y)
            else:
                return b"\x06" + ecdlp.itob(x) + ecdlp.itob(y)
        else:
            raise TypeError(f"Invalid mode {mode}")

    def bytes_to_point(self, p: bytes) -> Tuple[int, int]:
        """Convert bytes to point."""

        ecdlp = self._ecc.ecdlp
        length = ecdlp.length

        mode = p[0]
        if mode == 0x00:
            return ecdlp.INF

        point = p[1:]
        x = ecdlp.btoi(point[:length])
        if mode == 0x04 or mode == 0x06 or mode == 0x07:
            return x, ecdlp.btoi(point[length:])
        elif mode == 0x02 or mode == 0x03:
            y = ecdlp.get_y(x)
            if y < 0:
                raise errors.PointNotOnCurveError(x, -1)
            ylsb = y & 0x1
            if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
                return x, ecdlp.p - y
            return x, y
        else:
            raise errors.InvalidPCError(mode)

    @property
    def can_sign(self) -> bool:
        return bool(self._d and self._id)

    @property
    def can_verify(self) -> bool:
        return bool(self._xP and self._yP and self._id)

    @property
    def can_encrypt(self) -> bool:
        return bool(self._xP and self._yP)

    @property
    def can_decrypt(self) -> bool:
        return bool(self._d)

    @property
    def can_exchange_key(self) -> bool:
        return bool(self._d and self._id)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair.

        Returns:
            bytes: secret key
            bytes: public key point (xP, yP)
        """

        d, (x, y) = self._ecc.generate_keypair()
        P = self.point_to_bytes(x, y, self._pc_mode)
        return _itob(d), P

    def get_pubkey(self, d: bytes) -> bytes:
        """Get public key from secret key."""

        return self.point_to_bytes(*self._ecc.get_pubkey(_btoi(d)), self._pc_mode)

    def verify_pubkey(self, P: bytes) -> bool:
        """Verify if a public key is valid.

        Args:
            P (bytes): public key.

        Returns:
            (bool): Whether valid.
        """

        return self._ecc.verify_pubkey(self.bytes_to_point(P))

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Generate signature on message.

        Returns:
            bytes: r
            bytes: s
        """

        if not self.can_sign:
            raise errors.RequireArgumentError("sign", "d", "id")

        r, s = self._ecc.sign(message, self._d, self._id, self._xP, self._yP)
        return _itob(r), _itob(s)

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        """Verify a message and it's signature."""

        if not self.can_verify:
            raise errors.RequireArgumentError("verify", "P", "id")

        return self._ecc.verify(message, _btoi(r), _btoi(s), self._id, self._xP, self._yP)

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt

        Args:
            plain (bytes): plain text to be encrypted.
        """

        if not self.can_encrypt:
            raise errors.RequireArgumentError("encrypt", "P")

        C1, C2, C3 = self._ecc.encrypt(plain, self._xP, self._yP)

        cipher = bytearray()
        cipher.extend(self.point_to_bytes(*C1, self._pc_mode))
        cipher.extend(C3)
        cipher.extend(C2)

        return bytes(cipher)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt

        Raises:
            ValueError: Invalid PC byte.
        """

        if not self.can_decrypt:
            raise errors.RequireArgumentError("decrypt", "d")

        mode = cipher[0]
        if mode == 0x04 or mode == 0x06 or mode == 0x07:
            C1 = cipher[:1 + self._ecc.ecdlp.length * 2]
            c1_length = 1 + self._ecc.ecdlp.length * 2
        elif mode == 0x02 or mode == 0x03:
            C1 = cipher[:1 + self._ecc.ecdlp.length]
            c1_length = 1 + self._ecc.ecdlp.length
        else:
            raise errors.InvalidPCError(mode)

        hash_length = self._ecc._hash_cls.hash_length()
        C3 = cipher[c1_length:c1_length + hash_length]
        C2 = cipher[c1_length + hash_length:]

        return self._ecc.decrypt(*self.bytes_to_point(C1), C2, C3, self._d)

    def begin_key_exchange(self) -> Tuple[bytes, int]:
        """Begin key exchange.

        Returns:
            bytes: random point, will be sent to another user.
            int: t, will be used in next step.
        """

        if not self.can_exchange_key:
            raise errors.RequireArgumentError("key exchange", "d", "id")

        R, t = self._ecc.begin_key_exchange(self._d)
        return self.point_to_bytes(*R, self._pc_mode), t

    def _end_key_exchange_initiator(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes) -> bytes:
        """End key exchange for initiator.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of initiator.
            R (bytes): random point from responder.
            P (bytes): public key from responder.

        Returns:
            bytes: secret key of klen bytes.
        """

        xR, yR = self.bytes_to_point(R)
        xP, yP = self.bytes_to_point(P)

        U = self._ecc.get_secret_point(t, xR, yR, xP, yP)
        return self._ecc.generate_skey(klen, *U, self._id, self._xP, self._yP, id_, xP, yP)

    def _end_key_exchange_responder(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes) -> bytes:
        """End key exchange for responder.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of responder.
            R (bytes): random point from initiator.
            P (bytes): public key from initiator.

        Returns:
            bytes: secret key of klen bytes.
        """

        xR, yR = self.bytes_to_point(R)
        xP, yP = self.bytes_to_point(P)

        V = self._ecc.get_secret_point(t, xR, yR, xP, yP)
        return self._ecc.generate_skey(klen, *V, id_, xP, yP, self._id, self._xP, self._yP)

    def end_key_exchange(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes, mode: KEYXCHG_MODE) -> bytes:
        """End key exchange for initiator.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of self.
            R (bytes): random point from another user.
            P (bytes): public key from another user.
            mode (KEYXCHG_MODE): key exchange mode, initiator or responder.

        Returns:
            bytes: secret key of klen bytes.
        """

        if mode is KEYXCHG_MODE.INITIATOR:
            return self._end_key_exchange_initiator(klen, t, R, id_, P)
        elif mode is KEYXCHG_MODE.RESPONDER:
            return self._end_key_exchange_responder(klen, t, R, id_, P)
        else:
            raise TypeError(f"Invalid key exchange mode: {mode}")
