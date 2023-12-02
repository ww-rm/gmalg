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
        Y = x
        for X in range(1, p):
            U, V = self.lucas(X, Y, _4u1)

            if (V * V - 4 * Y) % p == 0:
                return (V * self.inv(2)) % p

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

    def addex(self, X: FpExEle, Y: FpExEle) -> FpExEle:
        return tuple((i + j) % self.p for i, j in zip(X, Y))

    def subex(self, X: FpExEle, Y: FpExEle) -> FpExEle:
        return tuple((i - j) % self.p for i, j in zip(X, Y))

    def mul2(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        x1, x0 = X
        y1, y0 = Y
        return ((x1 * y0 + x0 * y1) % self.p,
                (x0 * y0 - 2 * x1 * y1) % self.p)

    def inv2(self, X: Fp2Ele) -> Fp2Ele:
        x1, x0 = X
        invdet = self.inv(2 * x1 * x1 + x0 * x0, self.p)
        return ((-x1 * invdet) % self.p,
                (x0 * invdet) % self.p)

    def mul4(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        X1, X0 = X[:2], X[2:]
        Y1, Y0 = Y[:2], Y[2:]

    def inv4(self, X: Fp4Ele) -> Fp4Ele:
        ...

    def mul12(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        ...

    def inv12(self, X: Fp12Ele) -> Fp12Ele:
        ...

    def sqrt2(self, X: Fp2Ele) -> Fp2Ele:
        ...

    def sqrtex(self, X: FpExEle) -> FpExEle:
        ...

    def exele_to_bytes(self, e: FpExEle) -> bytes:
        """Convert extended domain elements to bytes."""

        ...

    def bytes_to_exele(self, b: bytes) -> FpExEle:
        """Convert bytes to extended domain elements."""

        ...
