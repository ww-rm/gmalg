import enum
import math
from typing import Callable, Tuple, Type

from . import errors
from .base import Hash, SMCoreBase
from .ellipticcurve import ECDLP, EcPoint
from .sm3 import SM3
from .utils import bytes_to_int, int_to_bytes

__all__ = [
    "SM2",
    "PC_MODE",
    "KEYXCHG_MODE",
]

_ecdlp = ECDLP(
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC,
    0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93,
    (0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7,
     0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0),
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123,
)


class SM2Core(SMCoreBase):
    """SM2 Core Algorithms."""

    def __init__(self, ecdlp: ECDLP, hash_cls: Type[Hash], rnd_fn: Callable[[int], int] = None) -> None:
        """Elliptic Curve Cipher

        Args:
            ecdlp (ECDLP): ECDLP used in cipher.
            hash_fn (Hash): hash function used in cipher.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.
        """

        super().__init__(hash_cls, rnd_fn)

        self.ecdlp = ecdlp

        # used in key exchange
        w = math.ceil(math.ceil(math.log2(self.ecdlp.fpn.p)) / 2) - 1
        self._2w = 1 << w
        self._2w_1 = self._2w - 1

    def generate_keypair(self) -> Tuple[int, EcPoint]:
        """Generate key pair."""

        d = self._randint(1, self.ecdlp.fpn.p - 2)
        return d, self.ecdlp.kG(d)

    def get_pubkey(self, d: int) -> EcPoint:
        """Generate public key by secret key d."""

        return self.ecdlp.kG(d)

    def verify_pubkey(self, P: EcPoint) -> bool:
        """Verify if a public key is valid."""
        ec = self.ecdlp.ec

        if P == ec.INF:
            return False

        if not ec.isvalid(P):
            return False

        if ec.mul(self.ecdlp.fpn.p, P) != ec.INF:
            return False

        return True

    def entity_info(self, id_: bytes, P: EcPoint) -> bytes:
        """Generate other entity information bytes.

        Raises:
            DataOverflowError: ID more than 2 bytes.
        """

        ENTL = len(id_) << 3
        if ENTL.bit_length() > 16:
            raise errors.DataOverflowError("ID", "2 bytes")

        etob = self.ecdlp.etob
        xP, yP = P
        xG, yG = self.ecdlp.G

        Z = bytearray()
        Z.extend(ENTL.to_bytes(2, "big"))
        Z.extend(id_)
        Z.extend(etob(self.ecdlp.ec.a))
        Z.extend(etob(self.ecdlp.ec.b))
        Z.extend(etob(xG))
        Z.extend(etob(yG))
        Z.extend(etob(xP))
        Z.extend(etob(yP))

        return self._hash_fn(Z)

    def sign(self, message: bytes, d: int, id_: bytes, P: EcPoint = None) -> Tuple[int, int]:
        """Generate signature on the message.

        Args:
            message (bytes): message to be signed.
            d (int): secret key.
            id_ (bytes): user id.
            xP (int): x of public key
            yP (int): y of public key

        Returns:
            (int, int): (r, s)
        """

        if P is None:
            P = self.get_pubkey(d)

        e = bytes_to_int(self._hash_fn(self.entity_info(id_, P) + message))

        ecdlp = self.ecdlp
        fpn = self.ecdlp.fpn
        while True:
            k = self._randint(1, fpn.p - 1)
            x, _ = ecdlp.kG(k)

            r = fpn.add(e, x)
            if fpn.iszero(r) or fpn.iszero(fpn.add(r, k)):
                continue

            s = fpn.mul(fpn.sub(k, fpn.mul(r, d)), fpn.inv(1 + d))
            if fpn.iszero(s):
                continue

            return r, s

    def verify(self, message: bytes, r: int, s: int, id_: bytes, P: EcPoint) -> bool:
        """Verify the signature on the message.

        Args:
            message (bytes): Message to be verified.
            r (int): r
            s (int): s
            id_ (bytes): user id.
            xP (int): x of public key.
            yP (int): y of public key.

        Returns:
            bool: Whether OK.
        """

        ec = self.ecdlp.ec
        fpn = self.ecdlp.fpn

        if r < 1 or r > fpn.p - 1:
            return False

        if s < 1 or s > fpn.p - 1:
            return False

        t = fpn.add(r, s)
        if fpn.iszero(t):
            return False

        e = int.from_bytes(self._hash_fn(self.entity_info(id_, P) + message), "big")

        x, _ = ec.add(self.ecdlp.kG(s), ec.mul(t, P))
        if fpn.add(e, x) != r:
            return False

        return True

    def encrypt(self, plain: bytes, P: EcPoint) -> Tuple[EcPoint, bytes, bytes]:
        """Encrypt.

        Args:
            data (bytes): plain text to be encrypted.
            xP (int): x of public key.
            yP (int): y of public key.

        Returns:
            (int, int): C1, kG point
            bytes: C2, cipher
            bytes: C3, hash value

        Raises:
            InfinitePointError: Infinite point encountered.

        The return order is `C1, C2, C3`, **NOT** `C1, C3, C2`.
        """

        ec = self.ecdlp.ec

        while True:
            k = self._randint(1, self.ecdlp.fpn.p - 1)
            x1, y1 = self.ecdlp.kG(k)  # C1

            if ec.mul(self.ecdlp.h, P) == ec.INF:
                raise errors.InfinitePointError(f"Infinite point encountered, [0x{self.ecdlp.h:x}](0x{P[0]:x}, 0x{P[1]:x})")

            x2, y2 = ec.mul(k, P)
            x2 = self.ecdlp.etob(x2)
            y2 = self.ecdlp.etob(y2)

            t = self._key_derivation_fn(x2 + y2, len(plain))
            if not any(t):
                continue

            C2 = bytes(map(lambda b1, b2: b1 ^ b2, plain, t))
            C3 = self._hash_fn(x2 + plain + y2)

            return (x1, y1), C2, C3

    def decrypt(self, C1: EcPoint, C2: bytes, C3: bytes, d: int) -> bytes:
        """Decrypt.

        Args:
            x1 (int): x of C1 (kG point).
            y1 (int): y of C1 (kG point).
            C1 (bytes, bytes): kG point
            C2 (bytes): cipher
            C3 (bytes): hash value
            d (int): secret key.

        Returns:
            bytes: plain text.

        Raises:
            PointNotOnCurveError: Invalid C1 point, not on curve.
            InfinitePointError: Infinite point encountered.
            UnknownError: Zero bytes key stream.
            CheckFailedError: Incorrect hash value.
        """

        ec = self.ecdlp.ec

        if not ec.isvalid(C1):
            raise errors.PointNotOnCurveError(C1)

        if ec.mul(self.ecdlp.h, C1) == ec.INF:
            raise errors.InfinitePointError(f"Infinite point encountered, [0x{self.ecdlp.h:x}](0x{C1[0]:x}, 0x{C1[1]:x})")

        x2, y2 = ec.mul(d, C1)
        x2 = self.ecdlp.etob(x2)
        y2 = self.ecdlp.etob(y2)

        t = self._key_derivation_fn(x2 + y2, len(C2))
        if not any(t):
            raise errors.UnknownError("Zero bytes key stream.")

        M = bytes(map(lambda b1, b2: b1 ^ b2, C2, t))

        if self._hash_fn(x2 + M + y2) != C3:
            raise errors.CheckFailedError("Incorrect hash value.")

        return M

    def _x_bar(self, x: int):
        """Used in key exchange."""

        return self._2w + (x & self._2w_1)

    def begin_key_exchange(self, d: int) -> Tuple[EcPoint, int]:
        """Generate data to begin key exchange.

        Returns:
            (int, int): random point, [r]G, r in [1, n - 1]
            int: t
        """

        ecdlp = self.ecdlp
        fpn = ecdlp.fpn

        r = self._randint(1, fpn.p - 1)
        R = ecdlp.kG(r)
        t = fpn.add(d, fpn.mul(self._x_bar(R[0]), r))

        return R, t

    def get_secret_point(self, t: int, R: EcPoint, P: EcPoint) -> EcPoint:
        """Generate session key of klen bytes for initiator.

        Args:
            t (int): generated from `begin_key_exchange`
            xR (int): x of random point from another user.
            yR (int): y of random point from another user.
            xP (int): x of public key of another user.
            yP (int): y of public key of another user.

        Returns:
            (int, int): The same secret point as another user.

        Raises:
            PointNotOnCurveError
            InfinitePointError
        """

        ec = self.ecdlp.ec

        if not ec.isvalid(R):
            raise errors.PointNotOnCurveError(R)

        S = ec.mul(self.ecdlp.h * t, ec.add(P, ec.mul(self._x_bar(R[0]), R)))

        if S == ec.INF:
            raise errors.InfinitePointError("Infinite point encountered.")

        return S

    def generate_skey(self, klen: int, S: EcPoint,
                      id_init: bytes, P_init: EcPoint,
                      id_resp: bytes, P_resp: EcPoint) -> bytes:
        """Generate secret key of klen bytes.

        Args:
            klen (int): key length in bytes to generate.
            x (int): x of secret point.
            y (int): y of secret point.

            id_init (bytes): id bytes of initiator.
            xP_init (int): x of public key of initiator.
            yP_init (int): y of public key of initiator.

            id_resp (bytes): id bytes of responder.
            xP_resp (int): x of public key of responder.
            yP_resp (int): y of public key of responder.

        Returns:
            bytes: secret key of klen bytes.
        """

        x, y = S

        Z = bytearray()

        Z.extend(self.ecdlp.etob(x))
        Z.extend(self.ecdlp.etob(y))
        Z.extend(self.entity_info(id_init, P_init))
        Z.extend(self.entity_info(id_resp, P_resp))

        return self._key_derivation_fn(Z, klen)


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

        self._core = SM2Core(_ecdlp, SM3, rnd_fn)
        self._d = bytes_to_int(d) if d else None

        if P:
            self._P = self.bytes_to_point(P)
        else:
            if self._d:
                self._P = self._core.get_pubkey(self._d)  # try generate public key
            else:
                self._P = None

        self._id = id_
        self._pc_mode = pc_mode

    def point_to_bytes(self, P: EcPoint, mode: PC_MODE) -> bytes:
        """Convert point to bytes."""

        ecdlp = self._core.ecdlp

        if P == ecdlp.ec.INF:
            return b"\x00"

        x, y = P

        if mode is PC_MODE.RAW:
            return b"\x04" + ecdlp.etob(x) + ecdlp.etob(y)
        elif mode is PC_MODE.COMPRESS:
            if y & 0x1:
                return b"\x03" + ecdlp.etob(x)
            else:
                return b"\x02" + ecdlp.etob(x)
        elif mode is PC_MODE.MIXED:
            if y & 0x1:
                return b"\x07" + ecdlp.etob(x) + ecdlp.etob(y)
            else:
                return b"\x06" + ecdlp.etob(x) + ecdlp.etob(y)
        else:
            raise TypeError(f"Invalid mode {mode}")

    def bytes_to_point(self, p: bytes) -> EcPoint:
        """Convert bytes to point."""

        ecdlp = self._core.ecdlp

        mode = p[0]
        if mode == 0x00:
            return ecdlp.ec.INF

        point = p[1:]
        x = ecdlp.btoe(point[:ecdlp.fp.e_length])
        if mode == 0x04 or mode == 0x06 or mode == 0x07:
            return x, ecdlp.btoe(point[ecdlp.fp.e_length:])
        elif mode == 0x02 or mode == 0x03:
            y = ecdlp.ec.get_y(x)
            if y < 0:
                raise errors.PointNotOnCurveError(x, -1)
            ylsb = y & 0x1
            if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
                return x, ecdlp.fp.neg(y)
            return x, y
        else:
            raise errors.InvalidPCError(mode)

    @property
    def can_sign(self) -> bool:
        return bool(self._d and self._id)

    @property
    def can_verify(self) -> bool:
        return bool(self._P and self._id)

    @property
    def can_encrypt(self) -> bool:
        return bool(self._P)

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

        d, P = self._core.generate_keypair()
        P = self.point_to_bytes(P, self._pc_mode)
        return int_to_bytes(d), P

    def get_pubkey(self, d: bytes) -> bytes:
        """Get public key from secret key."""

        return self.point_to_bytes(self._core.get_pubkey(bytes_to_int(d)), self._pc_mode)

    def verify_pubkey(self, P: bytes) -> bool:
        """Verify if a public key is valid.

        Args:
            P (bytes): public key.

        Returns:
            (bool): Whether valid.
        """

        return self._core.verify_pubkey(self.bytes_to_point(P))

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Generate signature on message.

        Returns:
            bytes: r
            bytes: s
        """

        if not self.can_sign:
            raise errors.RequireArgumentError("sign", "d", "id")

        r, s = self._core.sign(message, self._d, self._id, self._P)
        return int_to_bytes(r), int_to_bytes(s)

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        """Verify a message and it's signature."""

        if not self.can_verify:
            raise errors.RequireArgumentError("verify", "P", "id")

        return self._core.verify(message, bytes_to_int(r), bytes_to_int(s), self._id, self._P)

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt

        Args:
            plain (bytes): plain text to be encrypted.
        """

        if not self.can_encrypt:
            raise errors.RequireArgumentError("encrypt", "P")

        C1, C2, C3 = self._core.encrypt(plain, self._P)

        cipher = bytearray()
        cipher.extend(self.point_to_bytes(C1, self._pc_mode))
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

        length = self._core.ecdlp.fp.e_length
        mode = cipher[0]
        if mode == 0x04 or mode == 0x06 or mode == 0x07:
            C1 = cipher[:1 + length * 2]
            c1_length = 1 + length * 2
        elif mode == 0x02 or mode == 0x03:
            C1 = cipher[:1 + length]
            c1_length = 1 + length
        else:
            raise errors.InvalidPCError(mode)

        hash_length = self._core._hash_cls.hash_length()
        C3 = cipher[c1_length:c1_length + hash_length]
        C2 = cipher[c1_length + hash_length:]

        return self._core.decrypt(self.bytes_to_point(C1), C2, C3, self._d)

    def begin_key_exchange(self) -> Tuple[bytes, int]:
        """Begin key exchange.

        Returns:
            bytes: random point, will be sent to another user.
            int: t, will be used in next step.
        """

        if not self.can_exchange_key:
            raise errors.RequireArgumentError("key exchange", "d", "id")

        R, t = self._core.begin_key_exchange(self._d)
        return self.point_to_bytes(R, self._pc_mode), t

    def _end_key_exchange_initiator(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes) -> bytes:
        """End key exchange for initiator.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of initiator.
            R (bytes): random point from responder.
            id_ (bytes): id from responder.
            P (bytes): public key from responder.

        Returns:
            bytes: secret key of klen bytes.
        """

        R = self.bytes_to_point(R)
        P = self.bytes_to_point(P)

        U = self._core.get_secret_point(t, R, P)
        return self._core.generate_skey(klen, U, self._id, self._P, id_, P)

    def _end_key_exchange_responder(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes) -> bytes:
        """End key exchange for responder.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of responder.
            R (bytes): random point from initiator.
            id_ (bytes): id from initiator.
            P (bytes): public key from initiator.

        Returns:
            bytes: secret key of klen bytes.
        """

        R = self.bytes_to_point(R)
        P = self.bytes_to_point(P)

        V = self._core.get_secret_point(t, R, P)
        return self._core.generate_skey(klen, V, id_, P, self._id, self._P)

    def end_key_exchange(self, klen: int, t: int, R: bytes, id_: bytes, P: bytes, mode: KEYXCHG_MODE) -> bytes:
        """End key exchange for initiator.

        Args:
            klen (int): length of secret key in bytes to generate.
            t (int): t value of self.
            R (bytes): random point from another user.
            id_ (bytes): id from another user.
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
