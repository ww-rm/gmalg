import enum
import math
from typing import Callable, Tuple, Type

from . import ellipticcurve as Ec
from . import errors
from .base import KEYXCHG_MODE, PC_MODE, BlockCipher, Hash, SMCoreBase
from .sm3 import SM3
from .sm4 import SM4
from .utils import bytes_to_int, int_to_bytes

__all__ = [
    "SM9KGC",
    "SM9",
    "PC_MODE",
    "KEYXCHG_MODE",
]

_bnbp = Ec.BNBP(
    0x600000000058F98A,
    0x05,
    (1, 0),
    (0x93DE051D_62BF718F_F5ED0704_487D01D6_E1E40869_09DC3280_E8C4E481_7C66DDDD,
     0x21FE8DDA_4F21E607_63106512_5C395BBC_1C1C00CB_FA602435_0C464CD7_0A3EA616),
    ((0x85AEF3D0_78640C98_597B6027_B441A01F_F1DD2C19_0F5E93C4_54806C11_D8806141,
      0x37227552_92130B08_D2AAB97F_D34EC120_EE265948_D19C17AB_F9B7213B_AF82D65B),
     (0x17509B09_2E845C12_66BA0D26_2CBEE6ED_0736A96F_A347C8BD_856DC76B_84EBEB96,
      0xA7CF28D5_19BE3DA6_5F317015_3D278FF2_47EFBA98_A71A0811_6215BBA5_C999A7C7))
)


def point_to_bytes_1(P: Ec.EcPoint, mode: PC_MODE) -> bytes:
    """Convert point to bytes (Fp)."""

    if P == _bnbp.ec1.INF:
        return b"\x00"

    x, y = P

    if mode is PC_MODE.RAW:
        return b"\x04" + _bnbp.etob1(x) + _bnbp.etob1(y)
    elif mode is PC_MODE.COMPRESS:
        if y & 0x1:
            return b"\x03" + _bnbp.etob1(x)
        else:
            return b"\x02" + _bnbp.etob1(x)
    elif mode is PC_MODE.MIXED:
        if y & 0x1:
            return b"\x07" + _bnbp.etob1(x) + _bnbp.etob1(y)
        else:
            return b"\x06" + _bnbp.etob1(x) + _bnbp.etob1(y)
    else:
        raise TypeError(f"Invalid mode {mode}")


def bytes_to_point_1(p: bytes) -> Ec.EcPoint:
    """Convert bytes to point (Fp)."""

    mode = p[0]
    if mode == 0x00:
        return _bnbp.ec1.INF

    point = p[1:]
    x = _bnbp.btoe1(point[:_bnbp.fp1.e_length])
    if mode == 0x04 or mode == 0x06 or mode == 0x07:
        return x, _bnbp.btoe1(point[_bnbp.fp1.e_length:])
    elif mode == 0x02 or mode == 0x03:
        y = _bnbp.ec1.get_y(x)
        if y < 0:
            raise errors.PointNotOnCurveError(x, -1)
        ylsb = y & 0x1
        if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
            return x, _bnbp.fp1.neg(y)
        return x, y
    else:
        raise errors.InvalidPCError(mode)


def point_to_bytes_2(P: Ec.EcPoint2, mode: PC_MODE) -> bytes:
    """Convert point to bytes (Fp2)."""

    if P == _bnbp.ec2.INF:
        return b"\x00"

    x, y = P

    if mode is PC_MODE.RAW:
        return b"\x04" + _bnbp.etob2(x) + _bnbp.etob2(y)
    elif mode is PC_MODE.COMPRESS:
        if y[1] & 0x1:
            return b"\x03" + _bnbp.etob2(x)
        else:
            return b"\x02" + _bnbp.etob2(x)
    elif mode is PC_MODE.MIXED:
        if y[1] & 0x1:
            return b"\x07" + _bnbp.etob2(x) + _bnbp.etob2(y)
        else:
            return b"\x06" + _bnbp.etob2(x) + _bnbp.etob2(y)
    else:
        raise TypeError(f"Invalid mode {mode}")


def bytes_to_point_2(p: bytes) -> Ec.EcPoint2:
    """Convert bytes to point (Fp2)."""

    mode = p[0]
    if mode == 0x00:
        return _bnbp.ec2.INF

    point = p[1:]
    x = _bnbp.btoe2(point[:_bnbp.fp2.e_length])
    if mode == 0x04 or mode == 0x06 or mode == 0x07:
        return x, _bnbp.btoe2(point[_bnbp.fp2.e_length:])
    elif mode == 0x02 or mode == 0x03:
        y = _bnbp.ec2.get_y(x)
        if y < 0:
            raise errors.PointNotOnCurveError(x, -1)
        ylsb = y[1] & 0x1
        if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
            return x, _bnbp.fp2.neg(y)
        return x, y
    else:
        raise errors.InvalidPCError(mode)


class SM9Core(SMCoreBase):
    """SM9 Core"""

    def __init__(self, bnbp: Ec.BNBP, hash_cls: Type[Hash], bc_cls: Type[BlockCipher], rnd_fn: Callable[[int], int] = None) -> None:
        """ID Based Encryption.

        Args:
            bnbp (BNBP): BNBP used in SM9.
            hash_cls (Hash): hash class used in SM9.
            bc_cls (BlockCipher): block cipher used in SM9.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.
        """

        super().__init__(hash_cls, rnd_fn)
        self._bc_cls = bc_cls

        self.bnbp = bnbp
        self._hlen = math.ceil((5 * math.log2(bnbp.fpn.p)) / 32)

    def _cipher_fn(self, prefix_byte: bytes, Z: bytes, hlen: int) -> int:
        hash_fn = self._hash_fn
        v = self._hash_cls.hash_length()

        count, tail = divmod(hlen, v)
        if count + (tail > 0) > 0xffffffff:
            raise errors.DataOverflowError("cipher fn", f"{0xffffffff * v} bytes")

        Z = prefix_byte + Z

        Ha = bytearray()
        for ct in range(1, count + 1):
            Ha.extend(hash_fn(Z + ct.to_bytes(4, "big")))

        if tail > 0:
            Ha.extend(hash_fn(Z + (count + 1).to_bytes(4, "big"))[:tail])

        h = (int.from_bytes(Ha, "big") % (self.bnbp.fpn.p - 1)) + 1
        return h

    def _H1(self, Z: bytes) -> int:
        return self._cipher_fn(b"\x01", Z, self._hlen)

    def _H2(self, Z: bytes) -> int:
        return self._cipher_fn(b"\x02", Z, self._hlen)

    def _bc_encrypt(self, key: bytes, plain: bytes) -> bytes:
        return self._bc_cls(key).encrypt(plain)

    def _bc_decrypt(self, key: bytes, cipher: bytes) -> bytes:
        return self._bc_cls(key).decrypt(cipher)

    def _mac(self, key: bytes, Z: bytes) -> bytes:
        return self._hash_fn(Z + key)

    def generate_mpk_sign(self, msk_s: int) -> Ec.EcPoint2:
        """Generate master key for sign."""

        return self.bnbp.kG2(msk_s)

    def generate_keypair_sign(self) -> Tuple[int, Ec.EcPoint2]:
        """Generate masterkey pair for sign.

        Returns:
            int: master secretkey for sign.
            EcPoint2: master public key for sign.
        """

        msk_s = self._randint(1, self.bnbp.fpn.p - 1)
        return msk_s, self.generate_mpk_sign(msk_s)

    def generate_mpk_encrypt(self, msk_e: int) -> Ec.EcPoint:
        """Generate master key for encrypt."""

        return self.bnbp.kG1(msk_e)

    def generate_keypair_encrypt(self) -> Tuple[int, Ec.EcPoint]:
        """Generate master key pair for encrypt.

        Returns:
            int: master secret key for encrypt.
            EcPoint: master public key for encrypt.
        """

        msk_e = self._randint(1, self.bnbp.fpn.p - 1)
        return msk_e, self.generate_mpk_encrypt(msk_e)

    def generate_sk_sign(self, hid_s: bytes, msk_s: int, id_: bytes) -> Ec.EcPoint:
        """Generate user secret key for sign.

        Args:
            hid_s (bytes): sign function identity byte.
            msk_s (int): master secret key for sign.
            id_ (bytes): user id.

        Returns:
            EcPoint: user secret key for sign.
        """

        fpn = self.bnbp.fpn

        t1 = fpn.add(self._H1(id_ + hid_s), msk_s)
        if fpn.iszero(t1):
            raise errors.InvalidHidError("Sign key", hid_s)

        t2 = fpn.mul(msk_s, fpn.inv(t1))
        sk_s = self.bnbp.kG1(t2)
        return sk_s

    def generate_sk_encrypt(self, hid_e: bytes, msk_e: int, id_: bytes) -> Ec.EcPoint2:
        """Generate user secret key for encrypt.

        Args:
            hid_e (bytes): encrypt function identity byte.
            msk_e (int): master secret key for encrypt.
            id_ (bytes): user id.

        Returns:
            EcPoint2: user secret key for encrypt.
        """

        fpn = self.bnbp.fpn

        t1 = fpn.add(self._H1(id_ + hid_e), msk_e)
        if fpn.iszero(t1):
            raise errors.InvalidHidError("Encrypt key", hid_e)

        t2 = fpn.mul(msk_e, fpn.inv(t1))
        sk_e = self.bnbp.kG2(t2)
        return sk_e

    def sign(self, message: bytes, mpk_s: Ec.EcPoint2, sk_s: Ec.EcPoint) -> Tuple[int, Ec.EcPoint]:
        """Sign.

        Args:
            message (bytes): Message to be signed.
            mpk_s (EcPoint2): Master public key for sign.
            sk_s (EcPoint): User secret key for sign.

        Returns:
            int: h
            EcPoint: S
        """

        fpk = self.bnbp.fpk
        fpn = self.bnbp.fpn

        g = self.bnbp.eG1(mpk_s)

        while True:
            r = self._randint(1, fpn.p - 1)
            w = fpk.pow(g, r)
            h = self._H2(message + fpk.etob(w))
            l = fpn.sub(r, h)

            if fpn.iszero(l):
                continue

            S = self.bnbp.ec1.mul(l, sk_s)
            return h, S

    def verify(self, message: bytes, h: int, S: Ec.EcPoint, hid_s: bytes, mpk_s: Ec.EcPoint2, id_: bytes) -> bool:
        """Veerify.

        Args:
            message (bytes): Message to be verified.
            h (int): Generated by sign.
            S (EcPoint): Generated by sign.
            hid_s (bytes): sign function identity byte.
            mpk_s (EcPoint2): Master public key for sign.
            id_ (bytes): User id.

        Returns:
            bool: Whether OK.
        """

        if h < 1 or h > self.bnbp.fpn.p:
            return False

        fpk = self.bnbp.fpk
        ec1 = self.bnbp.ec1
        ec2 = self.bnbp.ec2
        if not ec1.isvalid(S):
            return False

        g = self.bnbp.eG1(mpk_s)
        t = fpk.pow(g, h)
        h1 = self._H1(id_ + hid_s)
        P = ec2.add(self.bnbp.kG2(h1), mpk_s)
        u = self.bnbp.e(S, P)
        w = fpk.mul(u, t)
        h2 = self._H2(message + fpk.etob(w))
        if h2 != h:
            return False

        return True


class SM9KGC:
    """SM9 KGC"""

    def __init__(self, hid_s: bytes = None, msk_s: bytes = None, mpk_s: bytes = None,
                 hid_e: bytes = None, msk_e: bytes = None, mpk_e: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW) -> None:
        """SM9 KGC

        Args:
            hid_s (btyes): Single byte for sign key generation.
            msk_s (bytes): Master secret key for sign.
            mpk_s (bytes): Master public key for sign.

            hid_e (btyes): Single byte for encrypt key generation.
            msk_e (bytes): Master secret key for encrypt.
            mpk_e (bytes): Master public key for encrypt.

            rnd_fn ((int) -> int): random function used to generate k-bit random number, default to `secrets.randbits`
        """

        self._core = SM9Core(_bnbp, SM3, SM4, rnd_fn)

        self._hid_s = hid_s
        self._msk_s = bytes_to_int(msk_s) if msk_s else None
        self._mpk_s = self._get_mpk_s(mpk_s)

        self._hid_e = hid_e
        self._msk_e = bytes_to_int(msk_e) if msk_e else None
        self._mpk_e = self._get_mpk_e(mpk_e)

        self._pc_mode = pc_mode

    def _get_mpk_s(self, mpk_s: bytes) -> Ec.EcPoint2:
        if mpk_s:
            return bytes_to_point_2(mpk_s)
        else:
            if self._msk_s:
                return self._core.generate_mpk_sign(self._msk_s)
            else:
                return None

    def _get_mpk_e(self, mpk_e: bytes) -> Ec.EcPoint:
        if mpk_e:
            return bytes_to_point_1(mpk_e)
        else:
            if self._msk_e:
                return self._core.generate_mpk_encrypt(self._msk_e)
            else:
                return None

    @property
    def can_generate_sk_sign(self) -> bool:
        return bool(self._msk_s and self._hid_s)

    @property
    def can_generate_sk_encrypt(self) -> bool:
        return bool(self._msk_e and self._hid_e)

    def generate_mpk_sign(self, msk_s: bytes) -> bytes:
        """Generate master key for sign."""

        mpk_s = self._core.generate_mpk_sign(bytes_to_int(msk_s))
        return point_to_bytes_2(mpk_s, self._pc_mode)

    def generate_keypair_sign(self) -> Tuple[bytes, bytes]:
        """Generate masterkey pair for sign.

        Returns:
            bytes: master secretkey for sign.
            bytes: master public key for sign.
        """

        msk_s, mpk_s = self._core.generate_keypair_sign()
        return int_to_bytes(msk_s), point_to_bytes_2(mpk_s, self._pc_mode)

    def generate_mpk_encrypt(self, msk_e: bytes) -> bytes:
        """Generate master key for encrypt."""

        mpk_e = self._core.generate_mpk_encrypt(bytes_to_int(msk_e))
        return point_to_bytes_1(mpk_e, self._pc_mode)

    def generate_keypair_encrypt(self) -> Tuple[bytes, bytes]:
        """Generate master key pair for encrypt.

        Returns:
            bytes: master secret key for encrypt.
            bytes: master public key for encrypt.
        """

        msk_e, mpk_e = self._core.generate_keypair_encrypt()
        return int_to_bytes(msk_e), point_to_bytes_1(mpk_e, self._pc_mode)

    def generate_sk_sign(self, id_: bytes) -> bytes:
        """Generate user secret key for sign.

        Args:
            msk_s (int): master secret key for sign.
            hid_s (bytes): sign function identity byte.
            id_ (bytes): user id.

        Returns:
            bytes: user secret key for sign.
        """

        if not self.can_generate_sk_sign:
            raise errors.RequireArgumentError("generate sk sign", "msk_s", "hid_s")

        sk_s = self._core.generate_sk_sign(self._hid_s, self._msk_s, id_)
        return point_to_bytes_1(sk_s, self._pc_mode)

    def generate_sk_encrypt(self, id_: bytes) -> bytes:
        """Generate user secret key for encrypt.

        Args:
            id_ (bytes): user id.

        Returns:
            bytes: user secret key for encrypt.
        """

        if not self.can_generate_sk_encrypt:
            raise errors.RequireArgumentError("generate sk encrypt", "msk_e", "hid_e")

        sk_e = self._core.generate_sk_encrypt(self._hid_e, self._msk_e, id_)
        return point_to_bytes_2(sk_e, self._pc_mode)


class SM9:
    """SM9"""

    def __init__(self, hid_s: bytes = None, mpk_s: bytes = None, sk_s: bytes = None,
                 hid_e: bytes = None, mpk_e: bytes = None, sk_e: bytes = None,
                 id_: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW) -> None:
        """SM9

        Args:
            hid_s (btyes): Single byte for sign key generation.
            mpk_s (bytes): Master public key for sign.
            sk_s (bytes): User secret key for sign.

            hid_e (btyes): Single byte for encrypt key generation.
            mpk_e (bytes): Master public key for encrypt.
            sk_e (bytes): User secret key for encrypt.

            rnd_fn ((int) -> int): random function used to generate k-bit random number, default to `secrets.randbits`
        """

        self._core = SM9Core(_bnbp, SM3, SM4, rnd_fn)

        self._hid_s = hid_s
        self._mpk_s = bytes_to_point_2(mpk_s) if mpk_s else None
        self._sk_s = bytes_to_point_1(sk_s) if sk_s else None

        self._hid_e = hid_e
        self._mpk_e = bytes_to_point_1(mpk_e) if mpk_e else None
        self._sk_e = bytes_to_point_2(sk_e) if sk_e else None

        self._id = id_
        self._pc_mode = pc_mode

    @property
    def can_sign(self) -> bool:
        return bool(self._mpk_s and self._sk_s)

    @property
    def can_verify(self) -> bool:
        return bool(self._hid_s and self._mpk_s and self._id)

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Sign.

        Args:
            message (bytes): Message to be signed.

        Returns:
            bytes: h
            bytes: S
        """

        if not self.can_sign:
            raise errors.RequireArgumentError("sign", "mpk_s", "sk_s")

        h, S = self._core.sign(message, self._mpk_s, self._sk_s)

        return int_to_bytes(h), point_to_bytes_1(S, self._pc_mode)

    def verify(self, message: bytes, h: bytes, S: bytes) -> bool:
        """Verify.

        Args:
            message (bytes): Message to be verified.
            h (bytes): h
            S (bytes): S

        Returns:
            bool: Whether OK.
        """

        if not self.can_verify:
            raise errors.RequireArgumentError("verify", "hid_s", "mpk_s", "id")

        return self._core.verify(message, bytes_to_int(h), bytes_to_point_1(S), self._hid_s, self._mpk_s, self._id)
