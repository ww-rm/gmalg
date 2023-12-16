"""SM2 Algorithm Implementation Module."""

import math
from typing import Callable, Tuple, Type

from . import ellipticcurve as Ec
from . import errors
from .base import KEYXCHG_MODE, PC_MODE, Hash, SMCoreBase
from .sm3 import SM3
from .utils import bytes_to_int, int_to_bytes

__all__ = [
    "SM2",
    "PC_MODE",
    "KEYXCHG_MODE",
]

_ecdlp = Ec.ECDLP(
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC,
    0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93,
    (0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7,
     0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0),
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123,
)


def point_to_bytes(P: Ec.EcPoint, mode: PC_MODE) -> bytes:
    """Convert point to bytes.

    Args:
        P (EcPoint): Point to be converted.
        mode: (PC_MODE): Compress mode.

    Returns:
        bytes: Converted point bytes.
    """

    if P == _ecdlp.ec.INF:
        return b"\x00"

    etob = _ecdlp.fp.etob
    x, y = P

    if mode is PC_MODE.RAW:
        return b"\x04" + etob(x) + etob(y)
    elif mode is PC_MODE.COMPRESS:
        if y & 0x1:
            return b"\x03" + etob(x)
        else:
            return b"\x02" + etob(x)
    elif mode is PC_MODE.MIXED:
        if y & 0x1:
            return b"\x07" + etob(x) + etob(y)
        else:
            return b"\x06" + etob(x) + etob(y)
    else:
        raise TypeError(f"Invalid mode {mode}")


def bytes_to_point(b: bytes) -> Ec.EcPoint:
    """Convert bytes to point.

    Args:
        b (bytes): Point bytes.

    Returns:
        EcPoint: Point converted.
    """

    fp = _ecdlp.fp
    ec = _ecdlp.ec

    mode = b[0]
    if mode == 0x00:
        return ec.INF

    point = b[1:]
    x = fp.btoe(point[:fp.e_length])
    if mode == 0x04 or mode == 0x06 or mode == 0x07:
        return x, fp.btoe(point[fp.e_length:])
    elif mode == 0x02 or mode == 0x03:
        y = ec.get_y(x)
        if y is None:
            raise errors.PointNotOnCurveError((x, y))
        ylsb = y & 0x1
        if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
            return x, fp.neg(y)
        return x, y
    else:
        raise errors.InvalidPCError(mode)


class SM2Core(SMCoreBase):
    """SM2 Core Algorithms.

    Attributes:
        ecdlp (ECDLP): ECDLP used in SM2.
    """

    def __init__(self, ecdlp: Ec.ECDLP, hash_cls: Type[Hash], rnd_fn: Callable[[int], int] = None) -> None:
        """SM2 Core Algorithms.

        Args:
            ecdlp (ECDLP): ECDLP used in SM2.
            hash_cls (Type[Hash]): Hash class used in SM2.
            rnd_fn (Callable[[int], int]): Random function used to generate k-bit random number, default to `secrets.randbits`.
        """

        super().__init__(hash_cls, rnd_fn)

        self.ecdlp = ecdlp

        # used in key exchange
        w = math.ceil(math.ceil(math.log2(self.ecdlp.fpn.p)) / 2) - 1
        self._2w = 1 << w
        self._2w_1 = self._2w - 1

    def generate_pk(self, sk: int) -> Ec.EcPoint:
        """Generate public key by secret key.

        Args:
            sk (int): Secret key.

        Returns:
            EcPoint: Point of public key.
        """

        return self.ecdlp.kG(sk)

    def generate_keypair(self) -> Tuple[int, Ec.EcPoint]:
        """Generate key pair.

        Returns:
            int: Secret key.
            EcPoint: Public key.
        """

        sk = self._randint(1, self.ecdlp.fpn.p - 2)
        return sk, self.generate_pk(sk)

    def verify_pk(self, pk: Ec.EcPoint) -> bool:
        """Verify if a public key is valid.

        Args:
            pk (EcPoint): Public key point.

        Returns:
            bool: Whether valid.
        """

        ec = self.ecdlp.ec

        if pk == ec.INF:
            return False

        if not ec.isvalid(pk):
            return False

        if ec.mul(self.ecdlp.fpn.p, pk) != ec.INF:
            return False

        return True

    def entity_info(self, uid: bytes, pk: Ec.EcPoint) -> bytes:
        """Generate other entity information bytes.

        Args:
            uid (bytes): User ID.
            pk (EcPoint): Public key point.

        Returns:
            bytes: User entity information.

        Raises:
            DataOverflowError: ID length more than 8192 bytes.
        """

        ENTL = len(uid) << 3
        if ENTL.bit_length() >= 16:
            raise errors.DataOverflowError("ID", "8192 bytes")

        etob = self.ecdlp.fp.etob
        xP, yP = pk
        xG, yG = self.ecdlp.G

        Z = bytearray()
        Z.extend(ENTL.to_bytes(2, "big"))
        Z.extend(uid)
        Z.extend(etob(self.ecdlp.ec.a))
        Z.extend(etob(self.ecdlp.ec.b))
        Z.extend(etob(xG))
        Z.extend(etob(yG))
        Z.extend(etob(xP))
        Z.extend(etob(yP))

        return self._hash_fn(Z)

    def sign(self, message: bytes, sk: int, uid: bytes, pk: Ec.EcPoint = None) -> Tuple[int, int]:
        """Generate signature on the message.

        Args:
            message (bytes): Message to be signed.
            sk (int): Secret key.
            uid (bytes): User ID.
            pk (EcPoint): Public key

        Returns:
            int: r.
            int: s.
        """

        if pk is None:
            pk = self.generate_pk(sk)

        e = bytes_to_int(self._hash_fn(self.entity_info(uid, pk) + message))

        ecdlp = self.ecdlp
        fpn = self.ecdlp.fpn
        while True:
            k = self._randint(1, fpn.p - 1)
            x, _ = ecdlp.kG(k)

            r = fpn.add(e, x)
            if fpn.iszero(r) or fpn.iszero(fpn.add(r, k)):
                continue

            s = fpn.mul(fpn.sub(k, fpn.mul(r, sk)), fpn.inv(1 + sk))
            if fpn.iszero(s):
                continue

            return r, s

    def verify(self, message: bytes, r: int, s: int, uid: bytes, pk: Ec.EcPoint) -> bool:
        """Verify the signature on the message.

        Args:
            message (bytes): Message to be verified.
            r (int): r
            s (int): s
            uid (bytes): User ID.
            pk (EcPoint): Public key.

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

        e = int.from_bytes(self._hash_fn(self.entity_info(uid, pk) + message), "big")

        x, _ = ec.add(self.ecdlp.kG(s), ec.mul(t, pk))
        if fpn.add(e, x) != r:
            return False

        return True

    def encrypt(self, plain: bytes, pk: Ec.EcPoint) -> Tuple[Ec.EcPoint, bytes, bytes]:
        """Encrypt.

        Args:
            plain (bytes): Plain text to be encrypted.
            pk (EcPoint): Public key.

        Returns:
            EcPoint: C1, kG point.
            bytes: C2, cipher.
            bytes: C3, hash value of cipher.

        Raises:
            InfinitePointError: Infinite point encountered.

        Note:
            The return order is `C1, C2, C3`, **NOT** `C1, C3, C2`.
        """

        ec = self.ecdlp.ec

        while True:
            k = self._randint(1, self.ecdlp.fpn.p - 1)
            x1, y1 = self.ecdlp.kG(k)  # C1

            if ec.mul(self.ecdlp.h, pk) == ec.INF:
                raise errors.InfinitePointError(f"Infinite point encountered, [0x{self.ecdlp.h:x}](0x{pk[0]:x}, 0x{pk[1]:x})")

            x2, y2 = ec.mul(k, pk)
            x2 = self.ecdlp.fp.etob(x2)
            y2 = self.ecdlp.fp.etob(y2)

            t = self._key_derivation_fn(x2 + y2, len(plain))
            if not any(t):
                continue

            C2 = bytes(map(lambda b1, b2: b1 ^ b2, plain, t))
            C3 = self._hash_fn(x2 + plain + y2)

            return (x1, y1), C2, C3

    def decrypt(self, C1: Ec.EcPoint, C2: bytes, C3: bytes, sk: int) -> bytes:
        """Decrypt.

        Args:
            C1 (EcPoint): kG point.
            C2 (bytes): Cipher.
            C3 (bytes): Hash value.
            sk (int): Secret key.

        Returns:
            bytes: Plain text.

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

        x2, y2 = ec.mul(sk, C1)
        x2 = self.ecdlp.fp.etob(x2)
        y2 = self.ecdlp.fp.etob(y2)

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

    def begin_key_exchange(self, sk: int) -> Tuple[Ec.EcPoint, int]:
        """Generate data to begin key exchange.

        Args:
            sk (int): Secret key.

        Returns:
            EcPoint: Random point.
            int: t
        """

        ecdlp = self.ecdlp
        fpn = ecdlp.fpn

        r = self._randint(1, fpn.p - 1)
        R = ecdlp.kG(r)
        t = fpn.add(sk, fpn.mul(self._x_bar(R[0]), r))

        return R, t

    def get_secret_point(self, t: int, R: Ec.EcPoint, pk: Ec.EcPoint) -> Ec.EcPoint:
        """Generate same secret point as another user.

        Args:
            t (int): Generated from `begin_key_exchange`
            R (EcPoint): Random point from another user.
            pk (EcPoint): Public key of another user.

        Returns:
            EcPoint: The same secret point as another user.

        Raises:
            PointNotOnCurveError: `R` not on curve..
            InfinitePointError: Secret point is infinite point.
        """

        ec = self.ecdlp.ec

        if not ec.isvalid(R):
            raise errors.PointNotOnCurveError(R)

        S = ec.mul(self.ecdlp.h * t, ec.add(pk, ec.mul(self._x_bar(R[0]), R)))

        if S == ec.INF:
            raise errors.InfinitePointError("Infinite point encountered.")

        return S

    def generate_skey(self, klen: int, S: Ec.EcPoint,
                      uid_init: bytes, pk_init: Ec.EcPoint,
                      uid_resp: bytes, pk_resp: Ec.EcPoint) -> bytes:
        """Generate secret key of klen bytes as same as another user.

        Args:
            klen (int): key length in bytes to generate.
            S (EcPoint): Secret point.

            uid_init (bytes): User ID bytes of initiator.
            pk_init (EcPoint): Public key of initiator.

            uid_resp (bytes): User ID bytes of responder.
            pk_resp (EcPoint): Public key of responder.

        Returns:
            bytes: Secret key of klen bytes.
        """

        x, y = S

        Z = bytearray()

        Z.extend(self.ecdlp.fp.etob(x))
        Z.extend(self.ecdlp.fp.etob(y))
        Z.extend(self.entity_info(uid_init, pk_init))
        Z.extend(self.entity_info(uid_resp, pk_resp))

        return self._key_derivation_fn(Z, klen)


class SM2:
    """SM2 Algorithm."""

    def __init__(self, sk: bytes = None, uid: bytes = None, pk: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW) -> None:
        """SM2 Algorithm.

        Args:
            sk (bytes): Secret key.
            pk (bytes): Public key.
            uid (bytes): User ID.

            rnd_fn (Callable[[int], int]): Random function used to generate k-bit random number, default to `secrets.randbits`.
            pc_mode (PC_MODE): Point compress mode used for generated data, no effects on the data to be parsed.
        """

        self._core = SM2Core(_ecdlp, SM3, rnd_fn)
        self._sk = bytes_to_int(sk) if sk else None
        self._pk = self._get_pk(pk)

        self._uid = uid
        self._pc_mode = pc_mode

    def _get_pk(self, pk: bytes) -> Ec.EcPoint:
        if pk:
            return bytes_to_point(pk)
        else:
            if self._sk:
                return self._core.generate_pk(self._sk)  # try generate public key
            else:
                return None

    @property
    def can_sign(self) -> bool:
        """Whether can do sign."""

        return bool(self._sk and self._uid)

    @property
    def can_verify(self) -> bool:
        """Whether can do verify."""

        return bool(self._pk and self._uid)

    @property
    def can_encrypt(self) -> bool:
        """Whether can do encrypt."""

        return bool(self._pk)

    @property
    def can_decrypt(self) -> bool:
        """Whether can do decrypt."""

        return bool(self._sk)

    @property
    def can_exchange_key(self) -> bool:
        """Whether can do key exchange."""

        return bool(self._sk and self._uid)

    def generate_pk(self, sk: bytes) -> bytes:
        """Generate public key from secret key.

        Args:
            sk (bytes): Secret key.

        Returns:
            bytes: Public key.
        """

        return point_to_bytes(self._core.generate_pk(bytes_to_int(sk)), self._pc_mode)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair.

        Returns:
            bytes: Secret key
            bytes: Public key.
        """

        sk, pk = self._core.generate_keypair()
        return int_to_bytes(sk), point_to_bytes(pk, self._pc_mode)

    def verify_pk(self, pk: bytes) -> bool:
        """Verify if a public key is valid.

        Args:
            pk (bytes): public key.

        Returns:
            bool: Whether valid.
        """

        return self._core.verify_pk(bytes_to_point(pk))

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Generate signature on message.

        Returns:
            bytes: r.
            bytes: s.

        Raises:
            RequireArgumentError: Missing some required arguments.
        """

        if not self.can_sign:
            raise errors.RequireArgumentError("sign", "sk", "ID")

        r, s = self._core.sign(message, self._sk, self._uid, self._pk)
        return int_to_bytes(r), int_to_bytes(s)

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        """Verify a message and it's signature.

        Args:
            message (bytes): Message to be signed.
            r (bytes): r of signature.
            s (bytes): s of signature.

        Returns:
            bool: Whether OK.

        Raises:
            RequireArgumentError: Missing some required arguments.
        """

        if not self.can_verify:
            raise errors.RequireArgumentError("verify", "pk", "ID")

        return self._core.verify(message, bytes_to_int(r), bytes_to_int(s), self._uid, self._pk)

    def encrypt(self, plain: bytes) -> bytes:
        """Encrypt.

        Args:
            plain (bytes): plain text to be encrypted.

        Returns:
            bytes: Cipher data.

        Raises:
            RequireArgumentError: Missing some required arguments.
        """

        if not self.can_encrypt:
            raise errors.RequireArgumentError("encrypt", "pk")

        C1, C2, C3 = self._core.encrypt(plain, self._pk)

        cipher = bytearray()
        cipher.extend(point_to_bytes(C1, self._pc_mode))
        cipher.extend(C3)
        cipher.extend(C2)

        return bytes(cipher)

    def decrypt(self, cipher: bytes) -> bytes:
        """Decrypt.

        Args:
            cipher (bytes): Cipher data.

        Returns:
            bytes: Plain data.

        Raises:
            RequireArgumentError: Missing some required arguments.
            InvalidPCError: Invalid PC byte.
        """

        if not self.can_decrypt:
            raise errors.RequireArgumentError("decrypt", "sk")

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

        return self._core.decrypt(bytes_to_point(C1), C2, C3, self._sk)

    def begin_key_exchange(self) -> Tuple[bytes, int]:
        """Begin key exchange.

        Returns:
            bytes: Random point, will be sent to another user.
            int: t, will be used in next step.

        Raises:
            RequireArgumentError: Missing some required arguments.
        """

        if not self.can_exchange_key:
            raise errors.RequireArgumentError("key exchange", "sk", "ID")

        R, t = self._core.begin_key_exchange(self._sk)
        return point_to_bytes(R, self._pc_mode), t

    def end_key_exchange(self, klen: int, t: int, R: bytes, uid: bytes, pk: bytes, mode: KEYXCHG_MODE) -> bytes:
        """End key exchange and get the secret key bytes.

        Args:
            klen (int): Length of secret key in bytes to generate.
            t (int): t value of self.
            R (bytes): Random point from another user.
            uid (bytes): ID of another user.
            pk (bytes): Public key of another user.
            mode (KEYXCHG_MODE): Key exchange mode, initiator or responder.

        Returns:
            bytes: Secret key of klen bytes.

        Raises:
            TypeError: Invalid key exchange mode.
        """

        R = bytes_to_point(R)
        pk = bytes_to_point(pk)
        S = self._core.get_secret_point(t, R, pk)

        if mode is KEYXCHG_MODE.INITIATOR:
            return self._core.generate_skey(klen, S, self._uid, self._pk, uid, pk)
        elif mode is KEYXCHG_MODE.RESPONDER:
            return self._core.generate_skey(klen, S, uid, pk, self._uid, self._pk)
        else:
            raise TypeError(f"Invalid key exchange mode: {mode}")
