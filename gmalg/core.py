from typing import Callable, Tuple, Type

__all__ = [
    "Hash",
    "BlockCipher",
    "ECDLP",
    "EllipticCurve",
    "EllipticCurveCipher",
]


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


class Hash:
    @classmethod
    @property
    def max_msg_length(self) -> int:
        raise NotImplementedError

    @classmethod
    @property
    def hash_length(self) -> int:
        raise NotImplementedError

    def __init__(self) -> None:
        raise NotImplementedError

    def update(self, data: bytes) -> None:
        raise NotImplementedError

    @property
    def value(self) -> bytes:
        raise NotImplementedError


class BlockCipher:
    @classmethod
    @property
    def key_length(self) -> int:
        raise NotImplementedError

    @classmethod
    @property
    def block_length(self) -> int:
        raise NotImplementedError

    def __init__(self, key: bytes) -> None:
        raise NotImplementedError

    def encrypt(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, block: bytes) -> bytes:
        raise NotImplementedError


class EllipticCurve:
    """Elliptic Curve (Fp)"""

    def __init__(self, p: int, a: int, b: int) -> None:
        self._p = p
        self._a = a
        self._b = b

    @property
    def bitlength(self) -> int:
        return self._p.bit_length()

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


class ECDLP:
    """Elliptic Curve Discrete Logarithm Problem"""

    def __init__(self, ec: EllipticCurve, xG: int, yG: int, n: int, h: int = 1) -> None:
        self.ec = ec
        self._xG = xG
        self._yG = yG
        self._n = n
        self._h = h

    @property
    def rank_bitlength(self) -> int:
        return self._n.bit_length()

    def kG(self, k: int) -> Tuple[int, int]:
        return self.ec.mul(k, self._xG, self._yG)


class EllipticCurveCipher:
    """Elliptic Curve Cipher"""

    def __init__(self, ecdlp: ECDLP, hash_cls: Type[Hash], rnd_fn: Callable[[int], int], *,
                 d: bytes = None, xP: bytes = None, yP: bytes = None, id_: bytes = None) -> None:
        """ECC

        Args:
            p (bytes): elliptic curve parameter `p`.
            a (bytes): elliptic curve parameter `a`.
            b (bytes): elliptic curve parameter `b`.

            n (bytes): ECDLP parameter `n`.
            xG (bytes): x of ECDLP parameter `G`.
            yG (bytes): y of ECDLP parameter `G`.

            hash_fn (Hash): hash function used in SM2.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.

            d (bytes): secret key.
            xP (bytes): x of public key.
            yP (bytes): y of public key.
            id_ (bytes): user id used in sign.
        """

        self._ecdlp = ecdlp

        self._hash_cls = hash_cls
        self._rnd_fn = rnd_fn

        self._d: int = int.from_bytes(d, "big") if d is not None else None
        self._xP: int = int.from_bytes(xP, "big") if xP is not None else None
        self._yP: int = int.from_bytes(yP, "big") if yP is not None else None
        self._id: bytes = id_

        # try generate public key
        if self._d is not None and (self._xP is None or self._yP is None):
            self._xP, self._yP = self._ecdlp.kG(self._d)

    def _hash_fn(self, data: bytes) -> bytes:
        hash_obj = self._hash_cls()
        hash_obj.update(data)
        return hash_obj.value

    def _randint(self, a: int, b: int) -> int:
        while True:
            n = self._rnd_fn(b.bit_length())
            if n < a or n > b:
                continue
            return n

    def generate_keypair(self) -> Tuple[bytes, Tuple[bytes, bytes]]:
        """Generate key pair.

        Returns:
            bytes: secret key
            (bytes, bytes): public key, (xP, yP)
        """

        d = self._randint(1, self._ecdlp._n - 2)
        xP, yP = self._ecdlp.kG(d)
        return (
            d.to_bytes((d.bit_length() + 7) >> 3, "big"),
            (xP.to_bytes((xP.bit_length() + 7 >> 3), "big"), yP.to_bytes((yP.bit_length() + 7) >> 3, "big"))
        )

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

        if self._ecdlp.ec.isinf(x, y):
            return False

        if not self._ecdlp.ec.isvalid(x, y):
            return False

        if not self._ecdlp.ec.isinf(self._ecdlp.ec.mul(self._ecdlp._n, x, y)):
            return False

        return True

    @property
    def can_sign(self) -> bool:
        return self._d is not None and self._id is not None

    @property
    def can_verify(self) -> bool:
        return self._xP is not None and self._yP is not None and self._id is not None

    @property
    def can_encrypt(self) -> bool:
        return self._xP is not None and self._yP is not None

    @property
    def can_decrypt(self) -> bool:
        return self._d is not None

    @property
    def _Z(self) -> bytes:
        ENTL = len(self._id) << 3
        if ENTL.bit_length() > 16:
            raise ValueError("ID bit length more than 2 bytes.")

        a = self._ecdlp.ec._a
        b = self._ecdlp.ec._b
        xG = self._ecdlp._xG
        yG = self._ecdlp._yG
        xP = self._xP
        yP = self._yP

        Z = bytearray()
        Z.extend(ENTL.to_bytes(2, "big"))
        Z.extend(self._id)
        Z.extend(a.to_bytes((a.bit_length() + 7 >> 3), "big"))
        Z.extend(b.to_bytes((b.bit_length() + 7 >> 3), "big"))
        Z.extend(xG.to_bytes((xG.bit_length() + 7 >> 3), "big"))
        Z.extend(yG.to_bytes((yG.bit_length() + 7 >> 3), "big"))
        Z.extend(xP.to_bytes((xP.bit_length() + 7 >> 3), "big"))
        Z.extend(yP.to_bytes((yP.bit_length() + 7 >> 3), "big"))

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

        ecdlp = self._ecdlp
        n = self._ecdlp._n
        d = self._d
        while True:
            k = self._randint(1, n - 1)

            x, _ = ecdlp.kG(k)
            r = (e + x) % n
            if r == 0 or (r + k == n):
                continue

            s = (_inv(1 + d, n) * (k - r * d)) % n
            if s == 0:
                continue
            break

        return (r.to_bytes((r.bit_length() + 7 >> 3), "big"), s.to_bytes((s.bit_length() + 7 >> 3), "big"))

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

        ecdlp = self._ecdlp
        n = self._ecdlp._n
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

        e = int.from_bytes(self._hash_fn(self._Z + message), "big")

        x, _ = ecdlp.ec.add(*ecdlp.kG(s), *ecdlp.ec.mul(t, xP, yP))
        R = (e + x) % n
        if R != r:
            return False

        return True

    def _KDF(self, Z: bytes, klen: int) -> bytes:
        """
        Args:
            klen (int): key byte length
        """

        hash_fn = self._hash_fn
        v = self._hash_cls.hash_length

        count, tail = divmod(klen, v)
        if count + (tail > 0) >= 0xffffffff:
            raise OverflowError("klen is too big.")

        K = bytearray()
        for ct in range(1, count + 1):
            K.extend(hash_fn(Z + ct.to_bytes(4, "big")))

        if tail > 0:
            K.extend(hash_fn(Z + (count + 1).to_bytes(4, "big"))[:tail])

        return bytes(K)

    def encrypt(self, plain: bytes) -> Tuple[Tuple[bytes, bytes], bytes, bytes]:
        """Encrypt

        Args:
            data (bytes): plain text to be encrypted.

        Returns:
            (bytes, bytes): C1, kG point
            bytes: C2, cipher
            bytes: C3, hash value

        Raises:
            ValueError: Infinite point encountered.

        The return order is `C1, C2, C3`, **NOT** `C1, C3, C2`.
        """

        if not self.can_encrypt:
            raise ValueError("Can't encrypt, missing required args, need 'xP' and 'yP'")

        while True:
            k = self._randint(1, self._ecdlp._n - 1)
            x1, y1 = self._ecdlp.kG(k)

            if self._ecdlp.ec.isinf(*self._ecdlp.ec.mul(self._ecdlp._h, self._xP, self._yP)):
                raise ValueError("Infinite point encountered.")

            x2, y2 = self._ecdlp.ec.mul(k, self._xP, self._yP)
            x2 = x2.to_bytes((x2.bit_length() + 7) >> 3, "big")
            y2 = y2.to_bytes((y2.bit_length() + 7) >> 3, "big")

            t = self._KDF(x2 + y2, len(plain))
            if int.from_bytes(t, "big") == 0:
                continue

            C1 = (x1.to_bytes((x1.bit_length() + 7 >> 3), "big"), y1.to_bytes((y1.bit_length() + 7 >> 3), "big"))
            C2 = bytes(map(lambda b1, b2: b1 ^ b2, plain, t))
            C3 = self._hash_fn(x2 + plain + y2)

            return C1, C2, C3

    def decrypt(self, x1: bytes, y1: bytes, C2: bytes, C3: bytes) -> bytes:
        """Decrypt.

        Args:
            x1 (bytes): x of C1 (kG point).
            y1 (bytes): y of C1 (kG point).
            C1 (bytes, bytes): kG point
            C2 (bytes): cipher
            C3 (bytes): hash value

        Returns:
            bytes: plain text.

        Raises:
            ValueError: Invalid C1 point, not on curve.
            ValueError: Infinite point encountered.
            ValueError: Invalid key stream.
            ValueError: Incorrect hash value.
        """

        if not self.can_decrypt:
            raise ValueError("Can't decrypt, missing required args, need 'd'")

        x1 = int.from_bytes(x1, "big")
        y1 = int.from_bytes(y1, "big")

        if not self._ecdlp.ec.isvalid(x1, y1):
            raise ValueError("Invalid C1 point, not on curve.")

        if self._ecdlp.ec.isinf(*self._ecdlp.ec.mul(self._ecdlp._h, x1, y1)):
            raise ValueError("Infinite point encountered.")

        x2, y2 = self._ecdlp.ec.mul(self._d, x1, y1)
        x2 = x2.to_bytes((x2.bit_length() + 7) >> 3, "big")
        y2 = y2.to_bytes((y2.bit_length() + 7) >> 3, "big")

        t = self._KDF(x2 + y2, len(C2))
        if int.from_bytes(t, "big") == 0:
            raise ValueError("Invalid key stream.")

        M = bytes(map(lambda b1, b2: b1 ^ b2, C2, t))

        u = self._hash_fn(x2 + M + y2)
        if u != C3:
            raise ValueError("Incorrect hash value.")

        return M
