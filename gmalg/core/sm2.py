from typing import Callable, Tuple
from .sm3 import SM3
import secrets

__all__ = ["SM2"]


_p = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF")
_a = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC")
_b = bytes.fromhex("28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93")
_n = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123")
_xG = bytes.fromhex("32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7")
_yG = bytes.fromhex("BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0")


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

    def __init__(self, d: bytes = None, xP: bytes = None, yP: bytes = None, id_: bytes = None, *,
                 p: bytes = None, a: bytes = None, b: bytes = None, n: bytes = None, xG: bytes = None, yG: bytes = None,
                 hash_fn: Callable[[bytes], bytes] = None, rnd_fn: Callable[[int], int] = None) -> None:
        """SM2.

        Args:
            d (bytes): secret key.
            xP (bytes): x of public key.
            yP (bytes): y of public key.
            id_ (bytes): user id used in sign.

            p (bytes): elliptic curve parameter `p`.
            a (bytes): elliptic curve parameter `a`.
            b (bytes): elliptic curve parameter `b`.

            n (bytes): ECDLP parameter `n`.
            xG (bytes): x of ECDLP parameter `G`.
            yG (bytes): y of ECDLP parameter `G`.

            hash_fn ((bytes) -> bytes): hash function used in SM2.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.
        """

        self._d: int = int.from_bytes(d, "big") if d is not None else None
        self._xP: int = int.from_bytes(xP, "big") if xP is not None else None
        self._yP: int = int.from_bytes(yP, "big") if yP is not None else None
        self._id: bytes = id_

        self._ec: EC = EC(int.from_bytes(p or _p, "big"), int.from_bytes(a or _a, "big"), int.from_bytes(b or _b, "big"))
        self._n: int = int.from_bytes(n or _n, "big")
        self._xG: int = int.from_bytes(xG or _xG, "big")
        self._yG: int = int.from_bytes(yG or _yG, "big")

        self._hash_fn = hash_fn or self._default_hash_fn
        self._rnd_fn = rnd_fn or self._default_rnd_fn

        # try generate pubkey
        if self._d is not None and (self._xP is None or self._yP is None):
            self._xP, self._yP = self._ec.mul(self._d, self._xG, self._yG)

    def _default_hash_fn(self, data: bytes) -> bytes:
        sm3 = SM3()
        sm3.update(data)
        return sm3.value

    def _default_rnd_fn(self, k: int) -> int:
        return secrets.randbits(k)

    def generate_keypair(self) -> Tuple[bytes, Tuple[bytes, bytes]]:
        """Generate key pair.

        Returns:
            bytes: secret key
            (bytes, bytes): public key, (xP, yP)
        """

        d_min = 1
        d_max = self._n - 2
        bit_len = self._n.bit_length()
        rnd = self._rnd_fn

        d = rnd(bit_len)
        while d < d_min or d > d_max:
            d = rnd(bit_len)

        xP, yP = self._ec.mul(d, self._xG, self._yG)

        return d.to_bytes(32, "big"), (xP.to_bytes(32, "big"), yP.to_bytes(32, "big"))

    def verify_pubkey(self, x: bytes, y: bytes) -> bool:
        """Verify if a public key is valid.

        Args:
            x (bytes): x
            y (bytes): y

        Returns:
            (bool): Whether OK.
        """

        x = int.from_bytes(x, "big")
        y = int.from_bytes(y, "big")

        if self._ec.isinf(x, y):
            return False

        if not self._ec.isvalid(x, y):
            return False

        if not self._ec.isinf(self._ec.mul(self._n, x, y)):
            return False

        return True

    @property
    def can_sign(self) -> bool:
        return self._d is not None and self._id is not None

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
        Z.extend(self._ec._a.to_bytes(32, "big"))
        Z.extend(self._ec._b.to_bytes(32, "big"))
        Z.extend(self._xG.to_bytes(32, "big"))
        Z.extend(self._yG.to_bytes(32, "big"))
        Z.extend(self._xP.to_bytes(32, "big"))
        Z.extend(self._yP.to_bytes(32, "big"))

        return self._hash_fn(Z)

    def sign(self, message: bytes) -> Tuple[bytes, bytes]:
        """Sign.

        Args:
            message (bytes): message to be signed.

        Returns:
            (bytes, bytes): (r, s)
        """

        if not self.can_sign:
            raise ValueError("Can't sign, missing required args, need 'd' and 'id_'")

        e = int.from_bytes(self._hash_fn(self._Z + message), "big")

        ec = self._ec
        n = self._n
        xG = self._xG
        yG = self._yG
        d = self._d
        bit_len = self._n.bit_length()
        rnd = self._rnd_fn
        k_min = 1
        k_max = self._n - 1
        while True:
            k = rnd(bit_len)
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

        ec = self._ec
        n = self._n
        xG = self._xG
        yG = self._yG
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
