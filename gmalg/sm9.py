import math
from typing import Callable, Tuple, Type

from . import ellipticcurve as Ec
from . import errors
from . import primefield as Fp
from .base import KEYXCHG_MODE, PC_MODE, Hash, SMCoreBase
from .sm3 import SM3
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

    etob = _bnbp.fp1.etob
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


def bytes_to_point_1(p: bytes) -> Ec.EcPoint:
    """Convert bytes to point (Fp)."""

    ec1 = _bnbp.ec1
    fp1 = _bnbp.fp1

    mode = p[0]
    if mode == 0x00:
        return ec1.INF

    point = p[1:]
    x = fp1.btoe(point[:fp1.e_length])
    if mode == 0x04 or mode == 0x06 or mode == 0x07:
        return x, fp1.btoe(point[fp1.e_length:])
    elif mode == 0x02 or mode == 0x03:
        y = ec1.get_y(x)
        if y is None:
            raise errors.PointNotOnCurveError((x, y))
        ylsb = y & 0x1
        if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
            return x, fp1.neg(y)
        return x, y
    else:
        raise errors.InvalidPCError(mode)


def point_to_bytes_2(P: Ec.EcPoint2, mode: PC_MODE) -> bytes:
    """Convert point to bytes (Fp2)."""

    if P == _bnbp.ec2.INF:
        return b"\x00"

    etob = _bnbp.fp2.etob
    x, y = P

    if mode is PC_MODE.RAW:
        return b"\x04" + etob(x) + etob(y)
    elif mode is PC_MODE.COMPRESS:
        if y[1] & 0x1:
            return b"\x03" + etob(x)
        else:
            return b"\x02" + etob(x)
    elif mode is PC_MODE.MIXED:
        if y[1] & 0x1:
            return b"\x07" + etob(x) + etob(y)
        else:
            return b"\x06" + etob(x) + etob(y)
    else:
        raise TypeError(f"Invalid mode {mode}")


def bytes_to_point_2(p: bytes) -> Ec.EcPoint2:
    """Convert bytes to point (Fp2)."""

    mode = p[0]
    if mode == 0x00:
        return _bnbp.ec2.INF

    point = p[1:]
    x = _bnbp.fp2.btoe(point[:_bnbp.fp2.e_length])
    if mode == 0x04 or mode == 0x06 or mode == 0x07:
        return x, _bnbp.fp2.btoe(point[_bnbp.fp2.e_length:])
    elif mode == 0x02 or mode == 0x03:
        y = _bnbp.ec2.get_y(x)
        if y is None:
            raise errors.PointNotOnCurveError((x, y))
        ylsb = y[1] & 0x1
        if mode == 0x02 and ylsb or mode == 0x03 and not ylsb:
            return x, _bnbp.fp2.neg(y)
        return x, y
    else:
        raise errors.InvalidPCError(mode)


class SM9Core(SMCoreBase):
    """SM9 Core Algorithms."""

    def __init__(self, bnbp: Ec.BNBP, hash_cls: Type[Hash], rnd_fn: Callable[[int], int] = None) -> None:
        """ID Based Encryption.

        Args:
            bnbp (BNBP): BNBP used in SM9.
            hash_cls (Type[Hash]): Hash class used in SM9.
            rnd_fn ((int) -> int): Random function used to generate k-bit random number.
        """

        super().__init__(hash_cls, rnd_fn)

        self.bnbp = bnbp
        self._hlen = math.ceil((5 * math.log2(bnbp.fpn.p)) / 32)  # used for H1 and H2

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

    def _mac(self, key: bytes, Z: bytes) -> bytes:
        return self._hash_fn(Z + key)

    def generate_mpk_sign(self, msk_s: int) -> Ec.EcPoint2:
        """Generate master key for sign."""

        return self.bnbp.kG2(msk_s)

    def generate_keypair_sign(self) -> Tuple[int, Ec.EcPoint2]:
        """Generate masterkey pair for sign.

        Returns:
            int: Master secret key for sign.
            EcPoint2: Master public key for sign.
        """

        msk_s = self._randint(1, self.bnbp.fpn.p - 1)
        return msk_s, self.generate_mpk_sign(msk_s)

    def generate_mpk_encrypt(self, msk_e: int) -> Ec.EcPoint:
        """Generate master key for encrypt."""

        return self.bnbp.kG1(msk_e)

    def generate_keypair_encrypt(self) -> Tuple[int, Ec.EcPoint]:
        """Generate master key pair for encrypt.

        Returns:
            int: Master secret key for encrypt.
            EcPoint: Master public key for encrypt.
        """

        msk_e = self._randint(1, self.bnbp.fpn.p - 1)
        return msk_e, self.generate_mpk_encrypt(msk_e)

    def generate_sk_sign(self, hid_s: bytes, msk_s: int, uid: bytes) -> Ec.EcPoint:
        """Generate user secret key for sign.

        Args:
            hid_s (bytes): Sign function identity byte.
            msk_s (int): Master secret key for sign.
            uid (bytes): User ID.

        Returns:
            EcPoint: User secret key for sign.

        Raises:
            InvalidUserKeyError: Encounter zero when generating, need regenerate master key pair and user keys..
        """

        fpn = self.bnbp.fpn

        t1 = fpn.add(self._H1(uid + hid_s), msk_s)
        if fpn.iszero(t1):
            raise errors.InvalidUserKeyError("sign", uid)

        t2 = fpn.mul(msk_s, fpn.inv(t1))
        sk_s = self.bnbp.kG1(t2)
        return sk_s

    def generate_sk_encrypt(self, hid_e: bytes, msk_e: int, uid: bytes) -> Ec.EcPoint2:
        """Generate user secret key for encrypt.

        Args:
            hid_e (bytes): Encrypt function identity byte.
            msk_e (int): Master secret key for encrypt.
            uid (bytes): User ID.

        Returns:
            EcPoint2: User secret key for encrypt.

        Raises:
            InvalidUserKeyError: Encounter zero when generating, need regenerate master key pair and user keys..
        """

        fpn = self.bnbp.fpn

        t1 = fpn.add(self._H1(uid + hid_e), msk_e)
        if fpn.iszero(t1):
            raise errors.InvalidUserKeyError("encrypt", uid)

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

        fp12 = self.bnbp.fp12
        fpn = self.bnbp.fpn

        g = self.bnbp.eG1(mpk_s)

        while True:
            r = self._randint(1, fpn.p - 1)
            w = fp12.pow(g, r)
            h = self._H2(message + fp12.etob(w))
            l = fpn.sub(r, h)

            if fpn.iszero(l):
                continue

            S = self.bnbp.ec1.mul(l, sk_s)
            return h, S

    def verify(self, message: bytes, h: int, S: Ec.EcPoint, hid_s: bytes, mpk_s: Ec.EcPoint2, uid: bytes) -> bool:
        """Verify.

        Args:
            message (bytes): Message to be verified.
            h (int): Generated by sign.
            S (EcPoint): Generated by sign.
            hid_s (bytes): Sign function identity byte.
            mpk_s (EcPoint2): Master public key for sign.
            uid (bytes): User ID.

        Returns:
            bool: Whether OK.
        """

        if h < 1 or h > self.bnbp.fpn.p:
            return False

        fp12 = self.bnbp.fp12
        ec1 = self.bnbp.ec1
        ec2 = self.bnbp.ec2
        if not ec1.isvalid(S):
            return False

        g = self.bnbp.eG1(mpk_s)
        t = fp12.pow(g, h)
        h1 = self._H1(uid + hid_s)
        P = ec2.add(self.bnbp.kG2(h1), mpk_s)
        u = self.bnbp.e(S, P)
        w = fp12.mul(u, t)
        h2 = self._H2(message + fp12.etob(w))
        if h2 != h:
            return False

        return True

    def begin_key_exchange(self, hid_e: bytes, mpk_e: Ec.EcPoint, uid: bytes) -> Tuple[int, Ec.EcPoint]:
        """Generate data to begin key exchange.

        Args:
            hid_e (bytes): Encryption identity byte.
            mpk_e (EcPoint): Master public key for encryption.
            uid (bytes): ID of another user.

        Returns:
            int: r.
            EcPoint: Random point, [r]Q.
        """

        Q = self.bnbp.ec1.add(self.bnbp.kG1(self._H1(uid + hid_e)), mpk_e)
        r = self._randint(1, self.bnbp.fpn.p - 1)
        R = self.bnbp.ec1.mul(r, Q)
        return r, R

    def get_secret_data(self, mpk_e: Ec.EcPoint, r: int, R: Ec.EcPoint, sk_e: Ec.EcPoint2) -> Tuple[Fp.Fp12Ele, Fp.Fp12Ele, Fp.Fp12Ele]:
        """Generate same secret point as another user.

        Args:
            mpk_e (EcPoint): Master public key for encryption.
            r (int): Random number generated by `begin_key_exchange`.
            R (EcPoint): Random point from another user.
            sk_e (EcPoint2): Secret key for encryption.

        Returns:
            Fp12Ele: g1.
            Fp12Ele: g2.
            Fp12Ele: g3.
        """

        bnbp = self.bnbp

        if not bnbp.ec1.isvalid(R):
            raise errors.PointNotOnCurveError(R)

        g1 = bnbp.fp12.pow(bnbp.eG2(mpk_e), r)
        g2 = bnbp.e(R, sk_e)
        g3 = bnbp.fp12.pow(g2, r)

        return g1, g2, g3

    def generate_skey(self, klen: int, g1: Fp.Fp12Ele, g2: Fp.Fp12Ele, g3: Fp.Fp12Ele,
                      uid_init: bytes, R_init: Ec.EcPoint,
                      uid_resp: bytes, R_resp: Ec.EcPoint) -> bytes:
        """Generate secret key of klen bytes as same as another user.

        Args:
            klen (int): Key length in bytes to generate.
            g1 (Fp12Ele): g1.
            g2 (Fp12Ele): g2.
            g3 (Fp12Ele): g3.

            uid_init (bytes): User ID bytes of initiator.
            R_init (EcPoint): Random point of initiator.

            uid_resp (bytes): User ID bytes of responder.
            R_resp (EcPoint): Random point of responder.

        Returns:
            bytes: Secret key of klen bytes.
        """

        fp1 = self.bnbp.fp1
        fp12 = self.bnbp.fp12

        Z = bytearray()

        Z.extend(uid_init)
        Z.extend(uid_resp)
        Z.extend(fp1.etob(R_init[0]))
        Z.extend(fp1.etob(R_init[1]))
        Z.extend(fp1.etob(R_resp[0]))
        Z.extend(fp1.etob(R_resp[1]))
        Z.extend(fp12.etob(g1))
        Z.extend(fp12.etob(g2))
        Z.extend(fp12.etob(g3))

        return self._key_derivation_fn(Z, klen)

    def encapsulate(self, hid_e: bytes, mpk_e: Ec.EcPoint, klen: int, uid: bytes) -> Tuple[bytes, Ec.EcPoint]:
        """Encapsulate secret key.

        Args:
            hid_e (bytes): Encryption identity byte.
            mpk_e (EcPoint): Master public key for encryption.
            klen (int): Key length in bytes to encapsulate.
            uid (bytes): ID of another user.

        Returns:
            bytes: Encapsulated secret key of `klen` bytes.
            EcPoint: Encapsulated cipher.
        """

        bnbp = self.bnbp

        Q = bnbp.ec1.add(bnbp.kG1(self._H1(uid + hid_e)), mpk_e)

        while True:
            r = self._randint(1, bnbp.fpn.p - 1)
            C = bnbp.ec1.mul(r, Q)

            g = bnbp.eG2(mpk_e)
            w = bnbp.fp12.pow(g, r)

            Z = bytearray()
            Z.extend(bnbp.fp1.etob(C[0]))
            Z.extend(bnbp.fp1.etob(C[1]))
            Z.extend(bnbp.fp12.etob(w))
            Z.extend(uid)

            K = self._key_derivation_fn(Z, klen)

            if not any(K):
                continue

            return K, C

    def decapsulate(self, C: Ec.EcPoint, klen: int, sk_e: Ec.EcPoint2, uid: bytes):
        """Decapsulate secret key.

        Args:
            C (EcPoint): Encapsulated cipher.
            klen (int): Key length in bytes to encapsulate.
            sk_e (EcPoint2): Secret key for encrypt.
            uid (bytes): User ID.

        Returns:
            bytes: Encapsulated secret key of `klen` bytes.

        Raises:
            PointNotOnCurveError: C not on curve.
            UnknownError: Zero secret key encountered.
        """

        bnbp = self.bnbp

        if not bnbp.ec1.isvalid(C):
            raise errors.PointNotOnCurveError(C)

        w = bnbp.e(C, sk_e)

        Z = bytearray()
        Z.extend(bnbp.fp1.etob(C[0]))
        Z.extend(bnbp.fp1.etob(C[1]))
        Z.extend(bnbp.fp12.etob(w))
        Z.extend(uid)

        K = self._key_derivation_fn(Z, klen)

        if not any(K):
            raise errors.UnknownError("Zero secret key encountered.")

        return K

    def encrypt(self, hid_e: bytes, mpk_e: Ec.EcPoint, plain: bytes, uid: bytes, mac_klen: int) -> Tuple[Ec.EcPoint, bytes, bytes]:
        """Encrypt.

        Args:
            hid_e (bytes): Encryption identity byte.
            mpk_e (EcPoint): Master public key for encryption.
            plain (bytes): Plain data.
            uid (bytes): ID of another user.
            mac_klen (int): MAC key length in bytes.

        Returns:
            EcPoint: C1, encapsulated cipher key.
            bytes: C2, cipher data.
            bytes: C3, MAC of plain data.
        """

        mlen = len(plain)
        K, C1 = self.encapsulate(hid_e, mpk_e, mlen + mac_klen, uid)
        K1, K2 = K[:mlen], K[mlen:]

        C2 = bytes(map(lambda b1, b2: b1 ^ b2, plain, K1))
        C3 = self._mac(K2, C2)

        return C1, C2, C3

    def decrypt(self, C1: Ec.EcPoint, C2: bytes, C3: bytes, sk_e: Ec.EcPoint2, uid: bytes, mac_klen: int) -> bytes:
        """Decrypt.

        Args:
            C1 (EcPoint): Encapsulated cipher key.
            C2 (bytes): Cipher data.
            C3 (bytes): MAC of plain data.
            sk_e (EcPoint2): Secret key for encrypt.
            uid (bytes): User ID.
            mac_klen (int): MAC key length in bytes.

        Returns:
            bytes: Plain data.

        Raises:
            CheckFailedError: Invalid MAC value.
        """

        mlen = len(C2)

        K = self.decapsulate(C1, mlen + mac_klen, sk_e, uid)
        K1, K2 = K[:mlen], K[mlen:]

        plain = bytes(map(lambda b1, b2: b1 ^ b2, C2, K1))

        u = self._mac(K2, C2)
        if u != C3:
            raise errors.CheckFailedError("Invalid MAC value.")

        return plain


class SM9KGC:
    """SM9 KGC."""

    def __init__(self, hid_s: bytes = None, msk_s: bytes = None, mpk_s: bytes = None,
                 hid_e: bytes = None, msk_e: bytes = None, mpk_e: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW) -> None:
        """SM9 KGC.

        Args:
            hid_s (btyes): Single byte for sign key generation.
            msk_s (bytes): Master secret key for sign.
            mpk_s (bytes): Master public key for sign.

            hid_e (btyes): Single byte for encrypt key generation.
            msk_e (bytes): Master secret key for encrypt.
            mpk_e (bytes): Master public key for encrypt.

            rnd_fn ((int) -> int): random function used to generate k-bit random number, default to `secrets.randbits`.
        """

        self._core = SM9Core(_bnbp, SM3, rnd_fn)

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
        """Generate master key pair for sign.

        Returns:
            bytes: Master secret key for sign.
            bytes: Master public key for sign.
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
            bytes: Master secret key for encrypt.
            bytes: Master public key for encrypt.
        """

        msk_e, mpk_e = self._core.generate_keypair_encrypt()
        return int_to_bytes(msk_e), point_to_bytes_1(mpk_e, self._pc_mode)

    def generate_sk_sign(self, uid: bytes) -> bytes:
        """Generate user secret key for sign.

        Args:
            uid (bytes): User ID.

        Returns:
            bytes: User secret key for sign.
        """

        if not self.can_generate_sk_sign:
            raise errors.RequireArgumentError("generate sk sign", "msk_s", "hid_s")

        sk_s = self._core.generate_sk_sign(self._hid_s, self._msk_s, uid)
        return point_to_bytes_1(sk_s, self._pc_mode)

    def generate_sk_encrypt(self, uid: bytes) -> bytes:
        """Generate user secret key for encrypt.

        Args:
            uid (bytes): User ID.

        Returns:
            bytes: User secret key for encrypt.
        """

        if not self.can_generate_sk_encrypt:
            raise errors.RequireArgumentError("generate sk encrypt", "msk_e", "hid_e")

        sk_e = self._core.generate_sk_encrypt(self._hid_e, self._msk_e, uid)
        return point_to_bytes_2(sk_e, self._pc_mode)


class SM9:
    """SM9."""

    def __init__(self, hid_s: bytes = None, mpk_s: bytes = None, sk_s: bytes = None,
                 hid_e: bytes = None, mpk_e: bytes = None, sk_e: bytes = None,
                 uid: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None, pc_mode: PC_MODE = PC_MODE.RAW, mac_klen: int = 32) -> None:
        """SM9.

        Args:
            hid_s (btyes): Single byte for sign key generation.
            mpk_s (bytes): Master public key for sign.
            sk_s (bytes): User secret key for sign.

            hid_e (btyes): Single byte for encrypt key generation.
            mpk_e (bytes): Master public key for encrypt.
            sk_e (bytes): User secret key for encrypt.

            uid (bytes): User ID.

            rnd_fn ((int) -> int): Random function used to generate k-bit random number, default to `secrets.randbits`.
            pc_mode (PC_MODE): Point compress mode used for generated data, no effects on the data to be parsed.
            mac_klen (int): MAC value key length in bytes, default to `32`.
        """

        self._core = SM9Core(_bnbp, SM3, rnd_fn)

        self._hid_s = hid_s
        self._mpk_s = bytes_to_point_2(mpk_s) if mpk_s else None
        self._sk_s = bytes_to_point_1(sk_s) if sk_s else None

        self._hid_e = hid_e
        self._mpk_e = bytes_to_point_1(mpk_e) if mpk_e else None
        self._sk_e = bytes_to_point_2(sk_e) if sk_e else None

        self._uid = uid
        self._pc_mode = pc_mode
        self._mac_klen = mac_klen

    @property
    def can_sign(self) -> bool:
        return bool(self._mpk_s and self._sk_s)

    @property
    def can_verify(self) -> bool:
        return bool(self._hid_s and self._mpk_s and self._uid)

    @property
    def can_exchange_key(self) -> bool:
        return bool(self._hid_e and self._mpk_e and self._sk_e and self._uid)

    @property
    def can_encapsulate(self) -> bool:
        return bool(self._hid_e and self._mpk_e)

    @property
    def can_decapsulate(self) -> bool:
        return bool(self._sk_e and self._uid)

    @property
    def can_encrypt(self) -> bool:
        return bool(self.can_encapsulate and self._mac_klen)

    @property
    def can_decrypt(self) -> bool:
        return bool(self.can_decapsulate and self._mac_klen)

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
            raise errors.RequireArgumentError("verify", "hid_s", "mpk_s", "ID")

        return self._core.verify(message, bytes_to_int(h), bytes_to_point_1(S), self._hid_s, self._mpk_s, self._uid)

    def begin_key_exchange(self, uid: bytes) -> Tuple[int, bytes]:
        """Begin key exchange.

        Args:
            uid (bytes): ID of another user.

        Returns:
            int: r, random number.
            bytes: Random point, will be sent to another user.
        """

        if not self.can_exchange_key:
            raise errors.RequireArgumentError("key exchange", "hid_e", "mpk_e", "sk_e", "ID")

        r, R = self._core.begin_key_exchange(self._hid_e, self._mpk_e, uid)
        return r, point_to_bytes_1(R, self._pc_mode)

    def end_key_exchange(self, klen: int, r: int, R: bytes, uid: bytes, R2: bytes, mode: KEYXCHG_MODE) -> bytes:
        """End key exchange and get the secret key bytes.

        Args:
            klen (int): Length of secret key in bytes to generate.
            r (int): Random number of self.
            R (bytes): Random point of self.
            uid (bytes): ID of another user.
            R2 (bytes): Random point of another user.
            mode (KEYXCHG_MODE): Key exchange mode, initiator or responder.

        Returns:
            bytes: Secret key of klen bytes.
        """

        R = bytes_to_point_1(R)
        R2 = bytes_to_point_1(R2)
        g1, g2, g3 = self._core.get_secret_data(self._mpk_e, r, R2, self._sk_e)

        if mode is KEYXCHG_MODE.INITIATOR:
            return self._core.generate_skey(klen, g1, g2, g3, self._uid, R, uid, R2)
        elif mode is KEYXCHG_MODE.RESPONDER:
            return self._core.generate_skey(klen, g2, g1, g3, uid, R2, self._uid, R)
        else:
            raise TypeError(f"Invalid key exchange mode: {mode}")

    def encapsulate(self, klen: int, uid: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret key.

        Args:
            klen (int): Key length in bytes to encapsulate.
            uid (bytes): ID of another user.

        Returns:
            bytes: Encapsulated secret key of `klen` bytes.
            bytes: Encapsulated cipher.
        """

        if not self.can_encapsulate:
            raise errors.RequireArgumentError("encapsulate", "hid_e", "mpk_e")

        K, C = self._core.encapsulate(self._hid_e, self._mpk_e, klen, uid)
        return K, point_to_bytes_1(C, self._pc_mode)

    def decapsulate(self, C: bytes, klen: int):
        """Decapsulate secret key.

        Args:
            C (bytes): Encapsulated cipher.
            klen (int): Key length in bytes to encapsulate.

        Returns:
            bytes: Encapsulated secret key of `klen` bytes.
        """

        if not self.can_decapsulate:
            raise errors.RequireArgumentError("decapsulate", "sk_e", "uid")

        return self._core.decapsulate(bytes_to_point_1(C), klen, self._sk_e, self._uid)

    def encrypt(self, plain: bytes, uid: bytes):
        """Encrypt.

        Args:
            plain (bytes): Plain data.
            uid (bytes): ID of another user.

        Returns:
            bytes: Cipher data.
        """

        if not self.can_encrypt:
            raise errors.RequireArgumentError("encrypt", "hid_e", "mpk_e", "mac_klen")

        C1, C2, C3 = self._core.encrypt(self._hid_e, self._mpk_e, plain, uid, self._mac_klen)

        cipher = bytearray()
        cipher.extend(point_to_bytes_1(C1, self._pc_mode))
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
            ValueError: Invalid PC byte.
        """

        if not self.can_decrypt:
            raise errors.RequireArgumentError("decrypt", "sk_e", "uid", "mac_klen")

        length = self._core.bnbp.fp1.e_length
        mode = cipher[0]
        if mode == 0x04 or mode == 0x06 or mode == 0x07:
            C1 = cipher[:1 + length * 2]
            c1_length = 1 + length * 2
        elif mode == 0x02 or mode == 0x03:
            C1 = cipher[:1 + length]
            c1_length = 1 + length
        else:
            raise errors.InvalidPCError(mode)

        mac_length = self._core._hash_cls.hash_length()
        C3 = cipher[c1_length:c1_length + mac_length]
        C2 = cipher[c1_length + mac_length:]

        return self._core.decrypt(bytes_to_point_1(C1), C2, C3, self._sk_e, self._uid, self._mac_klen)
