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


def _generate_lucas(X: int, Y: int, k: int, p: int) -> Tuple[int, int]:
    """Lucas Sequence, k begin at 0.

    Uk = X * Uk-1 - Y * Uk-2
    Vk = X * Vk-1 - Y * Vk-2

    (0, 2) -> (1, X) -> ...
    """

    delta = (X * X - 4 * Y) % p
    inv2 = _inv(2, p)

    U, V = 0, 2
    for i in f"{k:b}":
        U, V = (U * V) % p, ((V * V + delta * U * U) * inv2) % p
        if i == "1":
            U, V = ((X * U + V) * inv2) % p, ((X * V + delta * U) * inv2) % p

    return U, V


def _sqrt_4u3(x: int, p: int, u: int):
    """_sqrt_8u3 and _sqrt_8u7"""

    y = pow(x, u + 1, p)
    if (y * y) % p == x:
        return y
    return -1


def _sqrt_8u5(x: int, p: int, u: int):
    z = pow(x, 2 * u + 1, p)
    if z == 1:
        return pow(x, u + 1, p)
    if z == p - 1:
        return (2 * x * pow(4 * x, u, p)) % p
    return -1


def _sqrt_8u1(x: int, p: int, u: int):
    _4u1 = 4 * u + 1
    p_1 = p - 1
    Y = x
    for X in range(1, p):
        U, V = _generate_lucas(X, Y, _4u1, p)

        if (V * V - 4 * Y) % p == 0:
            return (V * _inv(2, p)) % p

        if U != 1 or U != p_1:
            return -1

    return -1


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


class EllipticCurve:
    """Elliptic Curve (Fp)"""

    INF = (-1, -1)

    @staticmethod
    def isinf(x: int, y: int) -> bool:
        """Check if a point is a infinite point."""

        return x < 0 or y < 0

    def __init__(self, p: int, a: int, b: int) -> None:
        """Elliptic Curve (Fp)

        y^2 = x^3 + ax + b (mod p)
        """

        self.p = p
        self.a = a
        self.b = b

        self.bitlength = self.p.bit_length()
        self.length = (self.bitlength + 7) >> 3

        self._u, self._r = divmod(self.p, 8)
        if self._r == 3 or self._r == 7:
            self.get_y = self._get_y_4u3
        elif self._r == 1:
            self.get_y = self._get_y_8u1
        elif self._r == 5:
            self.get_y = self._get_y_8u5
        else:
            raise ValueError(f"p is not a prime number: 0x{p:x}")

    def isvalid(self, x: int, y: int) -> bool:
        """Verify if a point is on the curve."""

        if x >= self.p or y >= self.p:
            return False

        if (y * y - x * x * x - self.a * x - self.b) % self.p != 0:
            return False

        return True

    def add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points. Negative numbers means infinite point."""

        a = self.a
        p = self.p

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

        return self.add(x1, y1, x2, self.p - y2)

    def mul(self, k: int, x: int, y: int) -> Tuple[int, int]:
        """Scalar multiplication by k."""

        xk = -1
        yk = -1

        for i in f"{k:b}":
            xk, yk = self.add(xk, yk, xk, yk)
            if i == "1":
                xk, yk = self.add(xk, yk, x, y)

        return xk, yk

    def get_y_sqr(self, x: int) -> int:
        return (x * x * x + self.a * x + self.b) % self.p

    def _get_y_4u3(self, x: int) -> int:
        return _sqrt_4u3(self.get_y_sqr(x), self.p, self._u)

    def _get_y_8u5(self, x: int) -> int:
        return _sqrt_8u5(self.get_y_sqr(x), self.p, self._u)

    def _get_y_8u1(self, x: int) -> int:
        return _sqrt_8u1(self.get_y_sqr(x), self.p, self._u)

    def get_y(self, x: int) -> int:
        """Get one of valid y of given x, -1 means no solution."""
        raise NotImplementedError("Unknown Error.")

    def itob(self, i: int) -> bytes:
        """Convert domain elements to bytes."""

        return i.to_bytes(self.length, "big")

    def btoi(self, b: bytes) -> int:
        """Convert bytes to domain elements"""

        return int.from_bytes(b, "big")


class ECDLP(EllipticCurve):
    """Elliptic Curve Discrete Logarithm Problem"""

    def __init__(self, p: int, a: int, b: int, xG: int, yG: int, n: int, h: int = 1) -> None:
        """Elliptic Curve Discrete Logarithm Problem

        Elliptic Curve (Fp): y^2 = x^3 + ax + b (mod p)

        Base point: (xG, yG)
        Order of the base point: n
        Cofactor: h
        """

        super().__init__(p, a, b)

        self.xG = xG
        self.yG = yG
        self.n = n
        self.h = h

    def kG(self, k: int) -> Tuple[int, int]:
        """Scalar multiplication of G by k."""

        return self.mul(k, self.xG, self.yG)


class EllipticCurveCipher:
    """Elliptic Curve Cipher"""

    def __init__(self, ecdlp: ECDLP, hash_cls: Type[Hash], rnd_fn: Callable[[int], int]) -> None:
        """Elliptic Curve Cipher

        Args:
            ecdlp (ECDLP): ECDLP used in cipher.
            hash_fn (Hash): hash function used in cipher.
            rnd_fn ((int) -> int): random function used to generate k-bit random number.
        """

        self.ecdlp = ecdlp
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

    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        """Generate key pair."""

        d = self._randint(1, self.ecdlp.n - 2)
        return d, self.ecdlp.kG(d)

    def get_pubkey(self, d: int) -> Tuple[int, int]:
        """Generate public key by secret key d."""

        return self.ecdlp.kG(d)

    def verify_pubkey(self, x: int, y: int) -> bool:
        """Verify if a public key is valid."""

        if self.ecdlp.isinf(x, y):
            return False

        if not self.ecdlp.isvalid(x, y):
            return False

        if not self.ecdlp.isinf(self.ecdlp.mul(self.ecdlp.n, x, y)):
            return False

        return True

    def _Z(self, id_: bytes, xP: int, yP: int) -> bytes:
        ENTL = len(id_) << 3
        if ENTL.bit_length() > 16:
            raise ValueError("ID bit length more than 2 bytes.")

        itob = self.ecdlp.itob

        Z = bytearray()
        Z.extend(ENTL.to_bytes(2, "big"))
        Z.extend(id_)
        Z.extend(itob(self.ecdlp.a))
        Z.extend(itob(self.ecdlp.b))
        Z.extend(itob(self.ecdlp.xG))
        Z.extend(itob(self.ecdlp.yG))
        Z.extend(itob(xP))
        Z.extend(itob(yP))

        return self._hash_fn(Z)

    def sign(self, message: bytes, d: int, id_: bytes, xP: int = None, yP: int = None) -> Tuple[int, int]:
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

        if xP is None or yP is None:
            xP, yP = self.get_pubkey(d)

        e = int.from_bytes(self._hash_fn(self._Z(id_, xP, yP) + message), "big")

        ecdlp = self.ecdlp
        n = self.ecdlp.n
        while True:
            k = self._randint(1, n - 1)
            x, _ = ecdlp.kG(k)

            r = (e + x) % n
            if r == 0 or (r + k == n):
                continue

            s = (_inv(1 + d, n) * (k - r * d)) % n
            if s == 0:
                continue

            return r, s

    def verify(self, message: bytes, r: int, s: int, id_: bytes, xP: int, yP: int) -> bool:
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

        ecdlp = self.ecdlp
        n = self.ecdlp.n

        if r < 1 or r > n - 1:
            return False

        if s < 1 or s > n - 1:
            return False

        t = (r + s) % n
        if t == 0:
            return False

        e = int.from_bytes(self._hash_fn(self._Z(id_, xP, yP) + message), "big")

        x, _ = ecdlp.add(*ecdlp.kG(s), *ecdlp.mul(t, xP, yP))
        if (e + x) % n != r:
            return False

        return True

    def _KDF(self, Z: bytes, klen: int) -> bytes:
        """
        Args:
            Z (bytes): secret byets.
            klen (int): key byte length
        """

        hash_fn = self._hash_fn
        v = self._hash_cls.hash_length()

        count, tail = divmod(klen, v)
        if count + (tail > 0) > 0xffffffff:
            raise OverflowError("klen is too big.")

        K = bytearray()
        for ct in range(1, count + 1):
            K.extend(hash_fn(Z + ct.to_bytes(4, "big")))

        if tail > 0:
            K.extend(hash_fn(Z + (count + 1).to_bytes(4, "big"))[:tail])

        return bytes(K)

    def encrypt(self, plain: bytes, xP: int, yP: int) -> Tuple[Tuple[int, int], bytes, bytes]:
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
            ValueError: Infinite point encountered.

        The return order is `C1, C2, C3`, **NOT** `C1, C3, C2`.
        """

        while True:
            k = self._randint(1, self.ecdlp.n - 1)
            x1, y1 = self.ecdlp.kG(k)  # C1

            if self.ecdlp.isinf(*self.ecdlp.mul(self.ecdlp.h, xP, yP)):
                raise ValueError("Infinite point encountered.")

            x2, y2 = self.ecdlp.mul(k, xP, yP)
            x2 = self.ecdlp.itob(x2)
            y2 = self.ecdlp.itob(y2)

            t = self._KDF(x2 + y2, len(plain))
            if not any(t):
                continue

            C2 = bytes(map(lambda b1, b2: b1 ^ b2, plain, t))
            C3 = self._hash_fn(x2 + plain + y2)

            return (x1, y1), C2, C3

    def decrypt(self, x1: int, y1: int, C2: bytes, C3: bytes, d: int) -> bytes:
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
            ValueError: Invalid C1 point, not on curve.
            ValueError: Infinite point encountered.
            ValueError: Invalid key stream.
            ValueError: Incorrect hash value.
        """

        if not self.ecdlp.isvalid(x1, y1):
            raise ValueError("Invalid C1 point, not on curve.")

        if self.ecdlp.isinf(*self.ecdlp.mul(self.ecdlp.h, x1, y1)):
            raise ValueError("Infinite point encountered.")

        x2, y2 = self.ecdlp.mul(d, x1, y1)
        x2 = self.ecdlp.itob(x2)
        y2 = self.ecdlp.itob(y2)

        t = self._KDF(x2 + y2, len(C2))
        if not any(t):
            raise ValueError("Invalid key stream.")

        M = bytes(map(lambda b1, b2: b1 ^ b2, C2, t))

        if self._hash_fn(x2 + M + y2) != C3:
            raise ValueError("Incorrect hash value.")

        return M

    def begin_key_exchange(self) -> Tuple[int, int]:
        """Generate data to begin key exchange."""
