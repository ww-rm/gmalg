from typing import Tuple

from . import errors
from . import primefield as Fp


class EllipticCurveBase:
    """Base class of Elliptic Curve (Fp)"""

    @classmethod
    def _get_fp(cls, p: int) -> Fp.PrimeFieldBase:
        raise NotImplementedError

    @classmethod
    def infpoint(cls) -> Tuple[Fp.FpEle, Fp.FpEle]:
        raise NotImplementedError

    @classmethod
    def isinf(cls, x: int, y: int) -> bool:
        """Check if a point is a infinite point."""
        raise NotImplementedError

    def __init__(self, p: int, a: Fp.FpEle, b: Fp.FpEle) -> None:
        """Elliptic Curve (Fp)

        y^2 = x^3 + ax + b (mod p)

        Raises:
            InvalidArgumentError: p is not a prime number.
        """

        self.a = a
        self.b = b
        self._fp = self._get_fp(p)

    @property
    def p(self) -> int:
        return self._fp.p

    @property
    def length(self) -> int:
        return self._fp.length

    def isvalid(self, x: Fp.FpEle, y: Fp.FpEle) -> bool:
        """Verify if a point is on the curve."""
        raise NotImplementedError

    def get_y_sqr(self, x: Fp.FpEle) -> Fp.FpEle:
        raise NotImplementedError

    def get_y(self, x: Fp.FpEle) -> Fp.FpEle:
        """Get one of valid y of given x, -1 means no solution."""
        raise NotImplementedError

    def add(self, x1: Fp.FpEle, y1: Fp.FpEle, x2: Fp.FpEle, y2: Fp.FpEle) -> Tuple[Fp.FpEle, Fp.FpEle]:
        """Add two points. Negative numbers means infinite point."""
        raise NotImplementedError

    def sub(self, x1: Fp.FpEle, y1: Fp.FpEle, x2: Fp.FpEle, y2: Fp.FpEle) -> Tuple[Fp.FpEle, Fp.FpEle]:
        """Sub two points."""
        raise NotImplementedError

    def mul(self, k: Fp.FpEle, x: Fp.FpEle, y: Fp.FpEle) -> Tuple[Fp.FpEle, Fp.FpEle]:
        """Scalar multiplication by k."""
        raise NotImplementedError


class EllipticCurve(EllipticCurveBase):
    """Elliptic Curve (Fp)"""

    @classmethod
    def _get_fp(cls, p: int) -> Fp.PrimeField:
        return Fp.PrimeField(p)

    @classmethod
    def infpoint(cls) -> Tuple[int, int]:
        return (-1, -1)

    @classmethod
    def isinf(cls, x: int, y: int) -> bool:
        return x < 0 or y < 0

    def isvalid(self, x: int, y: int) -> bool:
        if x >= self._fp.p or y >= self._fp.p:
            return False

        if (y * y - x * x * x - self.a * x - self.b) % self._fp.p != 0:
            return False

        return True

    def get_y_sqr(self, x: int) -> int:
        return (x * x * x + self.a * x + self.b) % self._fp.p

    def get_y(self, x: int) -> int:
        """Get one of valid y of given x, -1 means no solution."""
        return self._fp.sqrt(self.get_y_sqr(x))

    def add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        fp = self._fp

        if self.isinf(x1, y1):
            return x2, y2
        if self.isinf(x2, y2):
            return x1, y1
        if x1 == x2:
            if y1 == 0 and y2 == 0 or y1 + y2 == fp.p:
                return -1, -1
            elif y1 == y2:
                lam = (3 * x1 * x1 + self.a) * fp.inv(2 * y1)
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
        return self.add(x1, y1, x2, self._fp.p - y2)

    def mul(self, k: int, x: int, y: int) -> Tuple[int, int]:
        xk = -1
        yk = -1

        for i in f"{k:b}":
            xk, yk = self.add(xk, yk, xk, yk)
            if i == "1":
                xk, yk = self.add(xk, yk, x, y)

        return xk, yk


class EllipticCurve2(EllipticCurve):
    """Elliptic Curve (Fp2)"""

    @classmethod
    def _get_fp(cls, p: int) -> Fp.PrimeField2:
        return Fp.PrimeField2(p)

    @classmethod
    def infpoint(cls) -> Tuple[int, int]:
        return ((-1, ) * 2, (-1, ) * 2)

    @classmethod
    def isinf(cls, x: Fp.FpExEle, y: Fp.FpExEle) -> bool:
        return any(i < 0 for i in x) or any(i < 0 for i in y)

    def isvalid(self, x: Fp.FpExEle, y: Fp.FpExEle) -> bool:
        return self._fp.mul(y, y) == self.get_y_sqr(x)

    def get_y_sqr(self, x: Fp.FpExEle) -> Fp.FpExEle:
        fp = self._fp
        return fp.add(fp.pow(x, 3), fp.add(fp.mul(self.a, x), self.b))

    def get_y(self, x: Fp.Fp2Ele) -> Fp.Fp2Ele:
        raise NotImplementedError

    def add(self, x1: Fp.FpExEle, y1: Fp.FpExEle, x2: Fp.FpExEle, y2: Fp.FpExEle) -> Tuple[Fp.FpExEle, Fp.FpExEle]:
        fp = self._fp

        if self.isinf(x1, y1):
            return x2, y2
        if self.isinf(x2, y2):
            return x1, y1
        if x1 == x2:
            if fp.isoppo(y1, y2):
                return self.infpoint()
            elif y1 == y2:
                _t1 = fp.add(self.a, fp.smul(3, fp.mul(x1, x1)))
                _t2 = fp.inv(fp.smul(2, y1))
                lam = fp.mul(_t1, _t2)
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam = fp.mul(fp.sub(y2, y1), fp.inv(fp.sub(x2, x1)))

        x3 = tuple((i1 - i2 - i3) % fp.p for i1, i2, i3 in zip(fp.mul(lam, lam), x1, x2))
        y3 = fp.sub(fp.mul(lam, fp.sub(x1, x3)), y1)
        return x3, y3

    def sub(self, x1: Fp.FpExEle, y1: Fp.FpExEle, x2: Fp.FpExEle, y2: Fp.FpExEle) -> Tuple[Fp.FpExEle, Fp.FpExEle]:
        return self.add(x1, y1, x2, self._fp.neg(y2))

    def mul(self, k: int, x: Fp.FpExEle, y: Fp.FpExEle) -> Tuple[Fp.FpExEle, Fp.FpExEle]:
        xk, yk = x, y
        for i in f"{k:b}"[1:]:
            xk, yk = self.add(xk, yk, xk, yk)
            if i == "1":
                xk, yk = self.add(xk, yk, x, y)
        return xk, yk

    def _g_fn(self, xU: Fp.FpExEle, yU: Fp.FpExEle, xV: Fp.FpExEle, yV: Fp.FpExEle, xQ: Fp.FpExEle, yQ: Fp.FpExEle) -> Fp.FpExEle:
        """g(U, V)(Q)"""

        fp = self._fp

        if self.isinf(xU, yU) or self.isinf(xV, yV) or self.isinf(xQ, yQ):
            return fp.one()

        if xU == xV:
            if fp.isoppo(yU, yV):
                return fp.sub(xQ - xV)
            elif yU == yV:
                _t1 = fp.add(self.a, fp.smul(3, fp.mul(xV, xV)))
                _t2 = fp.inv(fp.smul(2, yV))
                lam = fp.mul(_t1, _t2)
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam = fp.mul(fp.sub(yU, yV), fp.inv(fp.sub(xU, xV)))

        _t = fp.mul(lam, fp.sub(xQ - xV))
        g = tuple((i1 - i2 + i3) % fp.p for i1, i2, i3 in zip(_t, yQ, yV))
        return g

    def miller(self, c: int, xP: Fp.FpExEle, yP: Fp.FpExEle, xQ: Fp.FpExEle, yQ: Fp.FpExEle) -> Fp.FpExEle:
        """Miller function."""

        fp = self._fp
        g = self._g_fn

        f = fp.one()
        xV, yV = xP, yP
        for i in f"{c:b}"[1:]:
            gVV = g(xV, yV, xV, yV, xQ, yQ)
            xV, yV = self.add(xV, yV)
            g2V = g(xV, yV, xV, fp.neg(yV), xQ, yQ)
            f = fp.mul(fp.mul(f, f), fp.mul(gVV, fp.inv(g2V)))

            if i == "1":
                gVP = g(xV, yV, xP, yP, xQ, yQ)
                xV, yV = self.add(xV, yV, xP, yP)
                gVaP = g(xV, yV, xV, fp.neg(yV), xQ, yQ)
                f = fp.mul(f, fp.mul(gVP, fp.inv(gVaP)))

        return f


class EllipticCurve4(EllipticCurve2):
    """Elliptic Curve (Fp4)"""

    @classmethod
    def _get_fp(cls, p: int) -> Fp.PrimeField4:
        return Fp.PrimeField4(p)

    @classmethod
    def infpoint(cls) -> Tuple[int, int]:
        return ((-1, ) * 4, (-1, ) * 4)


class EllipticCurve12(EllipticCurve2):
    """Elliptic Curve (Fp12)"""

    @classmethod
    def _get_fp(cls, p: int) -> Fp.PrimeField12:
        return Fp.PrimeField12(p)

    @classmethod
    def infpoint(cls) -> Tuple[int, int]:
        return ((-1, ) * 12, (-1, ) * 12)


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

    def etob(self, e: int) -> bytes:
        return self._fp.etob(e)

    def btoe(self, b: bytes) -> int:
        return self._fp.btoe(b)


class ECBIDH:
    ...
