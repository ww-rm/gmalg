from typing import Tuple

from . import errors
from .utils import inverse

Fp2Ele = Tuple[int, int]
Fp4Ele = Tuple[int, int, int, int]
Fp12Ele = Tuple[int, int, int, int, int, int, int, int, int, int, int, int]
FpExEle = Tuple[int, ...]


class PrimeField:
    """Fp operations."""

    def __init__(self, p: int) -> None:
        self.p = p
        self.bitlength = self.p.bit_length()
        self.length = (self.bitlength + 7) >> 3

        self._u, self._r = divmod(self.p, 8)
        if self._r == 1:
            self.sqrt = self._sqrt_8u1
        elif self._r == 3:
            self._u = self._u * 2
            self.sqrt = self._sqrt_4u3
        elif self._r == 5:
            self.sqrt = self._sqrt_8u5
        elif self._r == 7:
            self._u = self._u * 2 + 1
            self.sqrt = self._sqrt_4u3
        else:
            raise errors.InvalidArgumentError(f"0x{p:x} is not a prime number.")

    def inv(self, x: int):
        """Modular inverse of p."""

        return inverse(x, self.p)

    def lucas(self, X: int, Y: int, k: int) -> Tuple[int, int]:
        """Lucas Sequence, k begin at 0.

        Uk = X * Uk-1 - Y * Uk-2
        Vk = X * Vk-1 - Y * Vk-2

        Returns:
            (int, int): The k-th lucas value pair.
        """

        p = self.p

        delta = (X * X - 4 * Y) % p
        inv2 = self.inv(2)

        U, V = 0, 2
        for i in f"{k:b}":
            U, V = (U * V) % p, ((V * V + delta * U * U) * inv2) % p
            if i == "1":
                U, V = ((X * U + V) * inv2) % p, ((X * V + delta * U) * inv2) % p
        return U, V

    def _sqrt_4u3(self, x: int):
        """sqrt_8u3 and sqrt_8u7"""
        p = self.p
        u = self._u

        y = pow(x, u + 1, p)
        if (y * y) % p == x:
            return y
        return -1

    def _sqrt_8u5(self, x: int):
        p = self.p
        u = self._u

        z = pow(x, 2 * u + 1, p)
        if z == 1:
            return pow(x, u + 1, p)
        if z == p - 1:
            return (2 * x * pow(4 * x, u, p)) % p
        return -1

    def _sqrt_8u1(self, x: int):
        p = self.p
        p_1 = p - 1
        _4u1 = 4 * self._u + 1
        inv2 = self.inv(2)

        Y = x
        for X in range(1, p):
            U, V = self.lucas(X, Y, _4u1)

            if (V * V - 4 * Y) % p == 0:
                return (V * inv2) % p

            if U != 1 or U != p_1:
                return -1

        return -1

    def sqrt(self, x: int) -> int:
        """Square root."""
        raise NotImplementedError

    def ele_to_bytes(self, e: int) -> bytes:
        """Convert domain elements to bytes."""

        return e.to_bytes(self.length, "big")

    def bytes_to_ele(self, b: bytes) -> int:
        """Convert bytes to domain elements."""

        return int.from_bytes(b, "big")


class PrimeFiledEx(PrimeField):
    """Fp2, Fp4, Fp12 operations."""

    def iszeroex(self, X: FpExEle) -> bool:
        return all(i == 0 for i in X)

    def isoneex(self, X: FpExEle) -> bool:
        return all(i == 0 for i in X[:-1]) and X[-1] == 1

    def isoppoex(self, X: FpExEle, Y: FpExEle) -> bool:
        return all((i1 + i2) == self.p for i1, i2 in zip(X, Y))

    def addex(self, X: FpExEle, Y: FpExEle) -> FpExEle:
        return tuple((i1 + i2) % self.p for i1, i2 in zip(X, Y))

    def subex(self, X: FpExEle, Y: FpExEle) -> FpExEle:
        return tuple((i1 - i2) % self.p for i1, i2 in zip(X, Y))

    def negex(self, X: FpExEle) -> FpExEle:
        return tuple(self.p - i for i in X)

    def saddex(self, n: int, X: FpExEle) -> FpExEle:
        _X = list(X)
        _X[-1] = (X[-1] + n) % self.p
        return tuple(_X)

    def smulex(self, k: int, X: FpExEle) -> FpExEle:
        return tuple((k * i) % self.p for i in X)

    def mul2(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        x1, x0 = X
        y1, y0 = Y
        x1y1 = x1 * y1
        x0y0 = x0 * y0
        z1 = ((x1 + x0) * (y1 + y0) - x1y1 - x0y0) % self.p
        z0 = (x0y0 - 2 * x1y1) % self.p
        return z1, z0

    def inv2(self, X: Fp2Ele) -> Fp2Ele:
        x1, x0 = X
        invdet = self.inv(2 * x1 * x1 + x0 * x0)
        y1 = (-x1 * invdet) % self.p
        y0 = (x0 * invdet) % self.p
        return y1, y0

    def mul4(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        a, m = self.addex, self.mul2
        X1, X0 = X[:2], X[2:]
        Y1, Y0 = Y[:2], Y[2:]
        U = (1, 0)

        X1mY1 = m(X1, Y1)
        X0mY0 = m(X0, Y0)

        X1aX0_m_Y1aY0 = m(a(X1, X0), a(Y1, Y0))
        Z1 = tuple((i1 - i2 - i3) % self.p for i1, i2, i3 in zip(X1aX0_m_Y1aY0, X1mY1, X0mY0))
        Z0 = a(m(U, X1mY1), X0mY0)

        return Z1 + Z0

    def inv4(self, X: Fp4Ele) -> Fp4Ele:
        m, n, s = self.mul2, self.negex, self.subex
        X1, X0 = X[:2], X[2:]
        U = (1, 0)

        UmX1mX1_s_X0mX0 = s(m(U, m(X1, X1)), m(X0, X0))
        invdet = self.inv2(UmX1mX1_s_X0mX0)

        Y1 = m(X1, invdet)
        Y0 = m(n(X0), invdet)

        return Y1 + Y0

    def mul12(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        a, m = self.addex, self.mul4
        X2, X1, X0 = X[:4], X[4:8], X[8:]
        Y2, Y1, Y0 = Y[:4], Y[4:8], Y[8:]
        V = (0, 1, 0, 0)

        X2mY2, X1mY1, X0mY0 = m(X2, Y2), m(X1, Y1), m(X0, Y0)
        X2aX1, X2aX0, X1aX0 = a(X2, X1), a(X2, X0), a(X1, X0)
        Y2aY1, Y2aY0, Y1aY0 = a(Y2, Y1), a(Y2, Y0), a(Y1, Y0)

        X2aX1_m_Y2aY1 = m(X2aX1, Y2aY1)
        X2aX0_m_Y2aY0 = m(X2aX0, Y2aY0)
        X1aX0_m_Y1aY0 = m(X1aX0, Y1aY0)

        VmX2mY2 = m(V, X2mY2)
        X2mY1_a_X1Y2 = tuple((i1 - i2 - i3) % self.p for i1, i2, i3 in zip(X2aX1_m_Y2aY1, X2mY2, X1mY1))

        Z2 = tuple((i1 - i2 - i3 + i4) % self.p for i1, i2, i3, i4 in zip(X2aX0_m_Y2aY0, X2mY2, X0mY0, X1mY1))
        Z1 = tuple((i1 + i2 - i3 - i4) % self.p for i1, i2, i3, i4 in zip(VmX2mY2, X1aX0_m_Y1aY0, X1mY1, X0mY0))
        Z0 = a(m(V, X2mY1_a_X1Y2), X0mY0)

        return Z2 + Z1 + Z0

    def inv12(self, X: Fp12Ele) -> Fp12Ele:
        m, s = self.mul4, self.subex
        X2, X1, X0 = X[:4], X[4:8], X[8:]
        V = (0, 1, 0, 0)

        VmX2 = m(V, X2)
        VmX1 = m(V, X1)

        X1mX1_s_X2mX0 = s(m(X1, X1), m(X2, X0))
        VmX2mX2_s_X1X0 = s(m(VmX2, X2), m(X1, X0))
        X0mX0_s_VmX2mX1 = s(m(X0, X0), m(VmX2, X1))

        det = tuple((i1 + i2 + i3) % self.p for i1, i2, i3 in zip(m(VmX2, VmX2mX2_s_X1X0), m(VmX1, X1mX1_s_X2mX0), m(X0, X0mX0_s_VmX2mX1)))
        invdet = self.inv4(det)

        Y2 = m(X1mX1_s_X2mX0, invdet)
        Y1 = m(VmX2mX2_s_X1X0, invdet)
        Y0 = m(X0mX0_s_VmX2mX1, invdet)

        return Y2 + Y1 + Y0

    def sqrt2(self, X: Fp2Ele) -> Fp2Ele:
        ...

    def sqrtex(self, X: FpExEle) -> FpExEle:
        ...

    def exele_to_bytes(self, e: FpExEle) -> bytes:
        """Convert extended domain elements to bytes."""

        b = bytearray()
        for i in e:
            b.extend(self.ele_to_bytes(i))
        return bytes(b)

    def bytes_to_exele(self, b: bytes) -> FpExEle:
        """Convert bytes to extended domain elements."""

        length = self.length
        e = []
        for i in range(0, len(b) - length, length):
            e.append(self.bytes_to_ele(b[i:i+length]))
        return tuple(e)
