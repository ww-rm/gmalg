from typing import Callable, Tuple

from . import errors
from .primefield import (Fp2Ele, Fp4Ele, Fp12Ele, FpExEle, PrimeField,
                         PrimeFiledEx)


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
        self._fp = PrimeField(p)

    @property
    def p(self) -> int:
        return self._fp.p

    @property
    def length(self) -> int:
        return self._fp.length

    def isvalid(self, x: int, y: int) -> bool:
        """Verify if a point is on the curve."""

        if x >= self._fp.p or y >= self._fp.p:
            return False

        if (y * y - x * x * x - self.a * x - self.b) % self._fp.p != 0:
            return False

        return True

    def add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points. Negative numbers means infinite point."""

        fp = self._fp

        if self.isinf(x1, y1):
            return x2, y2
        if self.isinf(x2, y2):
            return x1, y1
        if x1 == x2:
            if y1 + y2 == fp.p:
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
        """Sub two points."""

        return self.add(x1, y1, x2, self._fp.p - y2)

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
        return (x * x * x + self.a * x + self.b) % self._fp.p

    def get_y(self, x: int) -> int:
        """Get one of valid y of given x, -1 means no solution."""
        return self._fp.sqrt(self.get_y_sqr(x))


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
        return self._fp.ele_to_bytes(e)

    def btoe(self, b: bytes) -> int:
        return self._fp.bytes_to_ele(b)


class EllipticCurveEx(EllipticCurve):
    """Elliptic Curve (Fp) over extended field."""

    INF2 = ((-1,) * 2, (-1,) * 2)
    INF4 = ((-1,) * 4, (-1,) * 4)
    INF12 = ((-1,) * 12, (-1,) * 12)

    @staticmethod
    def isinfex(x: FpExEle, y: FpExEle) -> bool:
        return any(i < 0 for i in x) or any(i < 0 for i in y)

    def __init__(self, p: int, a: int, b: int) -> None:
        super().__init__(p, a, b)

        self._fpex = PrimeFiledEx(p)

        self.add2 = self._mk_addex_fn(2)
        self.add4 = self._mk_addex_fn(4)
        self.add12 = self._mk_addex_fn(12)

        self.mul2 = self._mk_mulex_fn(2)
        self.mul4 = self._mk_mulex_fn(4)
        self.mul12 = self._mk_mulex_fn(12)

    def _mk_addex_fn(self, exlen: int) -> Callable[[FpExEle, FpExEle, FpExEle, FpExEle], Tuple[FpExEle, FpExEle]]:
        fpex = self._fpex
        if exlen == 2:
            INF = self.INF2
            mul = fpex.mul2
            inv = fpex.inv2
        elif exlen == 4:
            INF = self.INF4
            mul = fpex.mul4
            inv = fpex.inv4
        elif exlen == 12:
            INF = self.INF12
            mul = fpex.mul12
            inv = fpex.inv12
        else:
            raise NotImplementedError(f"Unsupported extension length: {exlen}.")

        def _addn(x1: FpExEle, y1: FpExEle, x2: FpExEle, y2: FpExEle) -> Tuple[FpExEle, FpExEle]:
            """Add two points. Negative numbers means infinite point."""

            if self.isinfex(x1, y1):
                return x2, y2
            if self.isinfex(x2, y2):
                return x1, y1
            if x1 == x2:
                if fpex.isoppoex(y1, y2):
                    return INF
                elif y1 == y2:
                    _t1 = fpex.saddex(self.a, fpex.smulex(3, mul(x1, x1)))
                    _t2 = inv(fpex.smulex(2, y1))
                    lam = mul(_t1, _t2)
                else:
                    raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
            else:
                lam = mul(fpex.subex(y2, y1), inv(fpex.subex(x2, x1)))

            x3 = tuple((i1 - i2 - i3) % fpex.p for i1, i2, i3 in zip(mul(lam, lam), x1, x2))
            y3 = fpex.subex(mul(lam, fpex.subex(x1, x3)), y1)
            return x3, y3

        return _addn

    def add2(self, x1: Fp2Ele, y1: Fp2Ele, x2: Fp2Ele, y2: Fp2Ele) -> Tuple[Fp2Ele, Fp2Ele]:
        """Add two points over extension 2. Negative numbers means infinite point."""
        raise NotImplementedError

    def add4(self, x1: Fp4Ele, y1: Fp4Ele, x2: Fp4Ele, y2: Fp4Ele) -> Tuple[Fp4Ele, Fp4Ele]:
        """Add two points over extension 4. Negative numbers means infinite point."""
        raise NotImplementedError

    def add12(self, x1: Fp12Ele, y1: Fp12Ele, x2: Fp12Ele, y2: Fp12Ele) -> Tuple[Fp12Ele, Fp12Ele]:
        """Add two points over extension 12. Negative numbers means infinite point."""
        raise NotImplementedError

    def _mk_mulex_fn(self, exlen: int) -> Callable[[int, FpExEle, FpExEle], Tuple[FpExEle, FpExEle]]:
        if exlen == 2:
            add = self.add2
        elif exlen == 4:
            add = self.add4
        elif exlen == 12:
            add = self.add12
        else:
            raise NotImplementedError(f"Unsupported extension length: {exlen}.")

        def _muln(k: int, x: FpExEle, y: FpExEle) -> Tuple[FpExEle, FpExEle]:
            """Scalar multiplication by k."""

            xk, yk = x, y

            for i in f"{k:b}"[1:]:
                xk, yk = add(xk, yk, xk, yk)
                if i == "1":
                    xk, yk = add(xk, yk, x, y)

            return xk, yk

        return _muln

    def mul2(self, k: int, x: Fp2Ele, y: Fp2Ele) -> Tuple[Fp2Ele, Fp2Ele]:
        """Scalar multiplication by k over extended 2."""
        raise NotImplementedError

    def mul4(self, k: int, x: Fp4Ele, y: Fp4Ele) -> Tuple[Fp4Ele, Fp4Ele]:
        """Scalar multiplication by k over extension 4."""
        raise NotImplementedError

    def mul12(self, k: int, x: Fp12Ele, y: Fp12Ele) -> Tuple[Fp12Ele, Fp12Ele]:
        """Scalar multiplication by k over extension 12."""
        raise NotImplementedError

    def get_y_sqr_2(self, x: Fp2Ele) -> int:
        raise NotImplementedError

    def get_y_sqr_4(self, x: Fp4Ele) -> int:
        raise NotImplementedError

    def get_y_sqr_12(self, x: Fp12Ele) -> int:
        raise NotImplementedError

    def get_y_2(self, x: Fp2Ele) -> int:
        raise NotImplementedError

    def get_y_4(self, x: Fp4Ele) -> int:
        raise NotImplementedError

    def get_y_12(self, x: Fp12Ele) -> int:
        raise NotImplementedError
