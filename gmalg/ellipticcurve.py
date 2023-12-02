from typing import Tuple

from . import errors
from .primefield import PrimeField, PrimeFiledEx


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

        Raises:
            InvalidArgumentError: p is not a prime number.
        """

        self.a = a
        self.b = b
        self.fp = PrimeField(p)

    def isvalid(self, x: int, y: int) -> bool:
        """Verify if a point is on the curve."""

        if x >= self.fp.p or y >= self.fp.p:
            return False

        if (y * y - x * x * x - self.a * x - self.b) % self.fp.p != 0:
            return False

        return True

    def add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points. Negative numbers means infinite point."""

        fp = self.fp
        a = self.a

        if self.isinf(x1, y1):
            return x2, y2
        if self.isinf(x2, y2):
            return x1, y1
        if x1 == x2:
            if y1 + y2 == fp.p:
                return -1, -1
            elif y1 == y2:
                lam = (3 * x1 * x1 + a) * fp.inv(2 * y1)
            else:
                raise errors.UnknownError(f"0x{y1:x} and 0x{y2:x} is neither equal nor opposite.")
        else:
            if x2 > x1:
                lam = (y2 - y1) * fp.inv(x2 - x1)
            else:
                lam = (y1 - y2) * fp.inv(x1 - x2)

        x3 = (lam * lam - x1 - x2) % fp.p
        y3 = (lam * (x1 - x3) - y1) % fp.p

        return x3, y3

    def sub(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Sub two points."""

        return self.add(x1, y1, x2, self.fp.p - y2)

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
        return (x * x * x + self.a * x + self.b) % self.fp.p

    def get_y(self, x: int) -> int:
        """Get one of valid y of given x, -1 means no solution."""
        return self.fp.sqrt(self.get_y_sqr(x))


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


class EllipticCurveEx(EllipticCurve):
    """Elliptic Curve (Fp) over extended field."""

    INF2 = ((-1,) * 2, (-1,) * 2)
    INF4 = ((-1,) * 4, (-1,) * 4)
    INF12 = ((-1,) * 12, (-1,) * 12)

    def __init__(self, p: int, a: int, b: int) -> None:
        super().__init__(p, a, b)
