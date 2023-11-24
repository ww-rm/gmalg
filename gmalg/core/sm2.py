from typing import Tuple

from .. import random as gmrnd
from .sm3 import SM3

__all__ = ["SM2"]


def _inv(x: int, p: int):
    r1 = p
    r2 = x
    t1 = 0
    t2 = 1
    while r2 > 0:
        q, r = divmod(r1, r2)
        r1 = r2
        r2 = r
        t = t1 - q * t2
        t1 = t2
        t2 = t
    return t1 % p


class EC:
    """Elliptic Curve (Fp)"""

    def __init__(self, p: int, a: int, b: int) -> None:
        self._p = p
        self._a = a
        self._b = b

    @staticmethod
    def isinf(x: int, y: int) -> bool:
        return x < 0 or y < 0

    def isvalid(self, x: int, y: int) -> bool:
        """Verify if a point is on the curve."""

        if x >= self._p or y >= self._p:
            return False

        if (y * y - x * x * x - self._a * x - self._b) % self._p != 0:
            return False

        return True

    def add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points. Negative numbers means infinite point."""

        a = self._a
        p = self._p

        if self.isinf(x1, y1):
            return x2, y2
        if self.isinf(x2, y2):
            return x1, y1
        if x1 == x2:
            if y1 + y2 == p:
                return -1, -1
            elif y1 == y2:
                lam = (3 * x1 * x1 + a) * _inv(2 * y1, p)
            else:
                raise ValueError(f"{hex(y1)} and {hex(y2)} is neither equal nor opposite.")
        else:
            if x2 > x1:
                lam = (y2 - y1) * _inv(x2 - x1, p)
            else:
                lam = (y1 - y2) * _inv(x1 - x2, p)

        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p

        return x3, y3

    def sub(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Sub two points."""

        return self.add(x1, y1, x2, self._p - y2)

    def mul(self, k: int, x: int, y: int) -> Tuple[int, int]:
        """k-multiply points."""

        xk = -1
        yk = -1

        for i in f"{k:b}":
            xk, yk = self.add(xk, yk, xk, yk)
            if i == "1":
                xk, yk = self.add(xk, yk, x, y)

        return xk, yk


class SM2:
    """SM2"""

    p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
    a = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
    b = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
    n = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
    xG = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
    yG = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0

    EC_BITLEN = 256

    def __init__(self, xP: bytes = None, yP: bytes = None, d: bytes = None, id_: bytes = None, *, rnd: gmrnd.Random = None) -> None:
        """SM2

        Args:
            xP (bytes): public key x
            yP (bytes): public key y
            d (bytes): secret key
            id_ (bytes): id used in sign
            rnd (Random): random object to get random bits, default to `gmalg.random.SecretsRandom`
        """

        self._xP = int.from_bytes(xP, "big") if xP is not None else None
        self._yP = int.from_bytes(yP, "big") if yP is not None else None
        self._d = int.from_bytes(d, "big") if d is not None else None
        self._id = id_
        self._rnd = rnd or gmrnd.SecretsRandom()

        self.ec = EC(self.p, self.a, self.b)

    def verify_pubkey(self, x: bytes, y: bytes) -> bool:
        """Verify if a public key is valid.

        Args:
            x (bytes): x
            y (bytes): y
        """

        x = int.from_bytes(x, "big")
        y = int.from_bytes(y, "big")

        if self.ec.isinf(x, y):
            return False

        if not self.ec.isvalid(x, y):
            return False

        if not self.ec.isinf(self.ec.mul(self.n, x, y)):
            return False

        return True

    def generate_keypair(self) -> Tuple[bytes, Tuple[bytes, bytes]]:
        """Generate key pair.

        Returns:
            bytes: secret key
            (bytes, bytes): public key, (xP, yP)
        """

        d_min = 1
        d_max = self.n - 2
        bit_len = self.EC_BITLEN
        rnd = self._rnd

        d = rnd.randbits(bit_len)
        while d < d_min or d > d_max:
            d = rnd.randbits(bit_len)

        xP, yP = self.ec.mul(d, self.xG, self.yG)

        return d.to_bytes(32, "big"), (xP.to_bytes(32, "big"), yP.to_bytes(32, "big"))

    @property
    def can_sign(self) -> bool:
        return self._xP is not None and self._yP is not None and self._id is not None and self._d is not None

    @property
    def can_verify(self) -> bool:
        return self._xP is not None and self._yP is not None and self._id is not None

    # @property
    # def can_encrypt(self) -> bool:
    #     return self._xP is not None and self._yP is not None

    # @property
    # def can_decrypt(self) -> bool:
    #     return self._d is not None

    @property
    def _Z(self) -> bytes:
        ENTL = len(self._id) * 8
        if ENTL.bit_length() > 16:
            raise ValueError("ID bit length more than 2 bytes.")

        Z = bytearray()
        Z.extend(ENTL.to_bytes(2, "big"))
        Z.extend(self._id)
        Z.extend(self.a.to_bytes(32, "big"))
        Z.extend(self.b.to_bytes(32, "big"))
        Z.extend(self.xG.to_bytes(32, "big"))
        Z.extend(self.yG.to_bytes(32, "big"))
        Z.extend(self._xP.to_bytes(32, "big"))
        Z.extend(self._yP.to_bytes(32, "big"))

        sm3 = SM3()
        sm3.update(Z)
        return sm3.value

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Sign.

        Args:
            message (bytes): message to be signed.

        Returns:
            (bytes, bytes): (r, s)
        """

        if not self.can_sign:
            raise ValueError("Can't sign, missing required args, need 'xP', 'yP', 'id_' and 'd'")

        M = self._Z + message
        sm3 = SM3()
        sm3.update(M)
        e = int.from_bytes(sm3.value, "big")

        ec = self.ec
        n = self.n
        xG = self.xG
        yG = self.yG
        d = self._d
        bit_len = self.EC_BITLEN
        rnd = self._rnd
        k_min = 1
        k_max = self.n - 1
        while True:
            k = rnd.randbits(bit_len)
            if k < k_min or k > k_max:
                continue

            x, _ = ec.mul(k, xG, yG)
            r = (e + x) % n
            if r == 0 or (r + k == n):
                continue

            s = (_inv(1 + d, n) * (k - r * d)) % n
            if s == 0:
                continue
            break

        return (r.to_bytes(32, "big"), s.to_bytes(32, "big"))

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        """Verify.

        Args:
            message (bytes): Message to be verified.
            r (bytes): r
            s (bytes): s

        Returns:
            bool: Whether OK.
        """

        if not self.can_verify:
            raise ValueError("Can't verify, missing required args, need 'xP', 'yP', 'id_'")

        ec = self.ec
        n = self.n
        xG = self.xG
        yG = self.yG
        xP = self._xP
        yP = self._yP

        r: int = int.from_bytes(r, "big")
        if r < 1 or r > n - 1:
            return False
        s: int = int.from_bytes(s, "big")
        if s < 1 or s > n - 1:
            return False

        t = (r + s) % n
        if t == 0:
            return False

        M = self._Z + message
        sm3 = SM3()
        sm3.update(M)
        e = int.from_bytes(sm3.value, "big")

        x, _ = ec.add(*ec.mul(s, xG, yG), *ec.mul(t, xP, yP))
        R = (e + x) % n
        if R != r:
            return False

        return True

    def encrypt(self) -> bytes:
        """"""

    def decrypt(self) -> bytes:
        """"""
