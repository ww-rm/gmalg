from typing import Tuple, Union

from . import errors

# towering method: 1-2-4-12
# [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
# [[[11, 5], [8, 2]], [[10, 4], [7, 1]], [[9, 3], [6, 0]]]

Fp2Ele = Tuple[int, int]
Fp4Ele = Tuple[Fp2Ele, Fp2Ele]
Fp12Ele = Tuple[Fp4Ele, Fp4Ele, Fp4Ele]
FpExEle = Union[int, Fp2Ele, Fp4Ele, Fp12Ele]


class PrimeFieldBase:
    """Base class of Fp operations."""

    @classmethod
    def zero(cls) -> FpExEle:
        """Get Zero."""
        raise NotImplementedError

    @classmethod
    def one(cls) -> FpExEle:
        """Get One."""
        raise NotImplementedError

    @classmethod
    def iszero(cls, x: FpExEle) -> bool:
        raise NotImplementedError

    @classmethod
    def isone(cls, x: FpExEle) -> bool:
        raise NotImplementedError

    @classmethod
    def extend(cls, x: FpExEle) -> FpExEle:
        """Extend element."""
        raise NotImplementedError

    def __init__(self, p: int) -> None:
        raise NotImplementedError

    def isoppo(self, x: FpExEle, y: FpExEle) -> bool:
        raise NotImplementedError

    def neg(self, x: FpExEle) -> FpExEle:
        raise NotImplementedError

    def sadd(self, n: int, x: FpExEle) -> FpExEle:
        """Scalar add."""
        raise NotImplementedError

    def smul(self, k: int, x: FpExEle) -> FpExEle:
        """Scalar mul."""
        raise NotImplementedError

    def add(self, x: FpExEle, y: FpExEle) -> FpExEle:
        raise NotImplementedError

    def sub(self, x: FpExEle, y: FpExEle) -> FpExEle:
        raise NotImplementedError

    def mul(self, x: FpExEle, y: FpExEle) -> FpExEle:
        raise NotImplementedError

    def inv(self, x: FpExEle) -> FpExEle:
        raise NotImplementedError

    def pow(self, x: FpExEle, e: int) -> FpExEle:
        raise NotImplementedError

    def sqrt(self, x: FpExEle) -> FpExEle:
        raise NotImplementedError

    def etob(self, e: FpExEle) -> bytes:
        """Convert domain element to bytes."""
        raise NotImplementedError

    def btoe(self, b: bytes) -> FpExEle:
        """Convert bytes to domain element."""
        raise NotImplementedError


class PrimeField(PrimeFieldBase):
    """Fp operations."""

    @classmethod
    def zero(cls) -> int:
        return 0

    @classmethod
    def one(cls) -> int:
        return 1

    @classmethod
    def iszero(cls, x: int) -> bool:
        return x == 0

    @classmethod
    def isone(cls, x: int) -> bool:
        return x == 1

    @classmethod
    def extend(cls, x: int) -> int:
        return x

    def __init__(self, p: int) -> None:
        self.p = p
        self.p_bitlength = self.p.bit_length()
        self.p_length = (self.p_bitlength + 7) >> 3
        self.e_length = self.p_length

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

    def isoppo(self, x: int, y: int) -> bool:
        return x == 0 and y == 0 or x + y == self.p

    def neg(self, x: int) -> int:
        return self.p - x if x > 0 else x

    def sadd(self, n: int, x: int) -> int:
        return (n + x) % self.p

    def smul(self, k: int, x: int) -> int:
        return (k * x) % self.p

    def add(self, x: int, y: int) -> int:
        return (x + y) % self.p

    def sub(self, x: int, y: int) -> int:
        return (x - y) % self.p

    def mul(self, x: int, y: int) -> int:
        return (x * y) % self.p

    def inv(self, x: int):
        """Modular inverse."""

        x %= self.p

        r1 = self.p
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
        return t1 % self.p

    def pow(self, x: int, e: int) -> int:
        return pow(x, e, self.p)

    def _lucas(self, X: int, Y: int, k: int) -> Tuple[int, int]:
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
            U, V = self._lucas(X, Y, _4u1)

            if (V * V - 4 * Y) % p == 0:
                return (V * inv2) % p

            if U != 1 or U != p_1:
                return -1

        return -1

    def sqrt(self, x: int) -> int:
        """Square root."""
        raise NotImplementedError

    def etob(self, e: int) -> bytes:
        """Convert domain element to bytes."""
        return e.to_bytes(self.e_length, "big")

    def btoe(self, b: bytes) -> int:
        """Convert bytes to domain element."""
        return int.from_bytes(b, "big")


class PrimeField2(PrimeFieldBase):
    """Fp2 operations."""

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele]) -> Fp2Ele:
        if isinstance(x, int):
            return (PrimeField.zero(), PrimeField.extend(x))
        return x

    @classmethod
    def zero(cls) -> Fp2Ele:
        return (PrimeField.zero(), PrimeField.zero())

    @classmethod
    def one(cls) -> Fp2Ele:
        return (PrimeField.zero(), PrimeField.one())

    @classmethod
    def iszero(self, X: Fp2Ele) -> bool:
        return all(PrimeField.iszero(i) for i in X)

    @classmethod
    def isone(self, X: Fp2Ele) -> bool:
        return all(PrimeField.iszero(i) for i in X[:-1]) and PrimeField.isone(X[-1])

    def __init__(self, p: int) -> None:
        self._fp = PrimeField(p)
        self.e_length = self._fp.e_length * 2

    def isoppo(self, X: Fp2Ele, Y: Fp2Ele) -> bool:
        return all(self._fp.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp2Ele) -> Fp2Ele:
        return tuple(self._fp.neg(i) for i in X)

    def sadd(self, n: int, x: Fp2Ele) -> Fp2Ele:
        x = list(x)
        x[-1] = self._fp.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp2Ele) -> Fp2Ele:
        return tuple(self._fp.smul(k, i) for i in x)

    def add(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        return tuple(self._fp.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        return tuple(self._fp.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        a = self._fp.add
        s = self._fp.sub
        m = self._fp.mul

        X1, X0 = X
        Y1, Y0 = Y
        U = -2

        X1mY1 = m(X1, Y1)
        X0mY0 = m(X0, Y0)

        X1aX0_m_Y1aY0 = m(a(X1, X0), a(Y1, Y0))
        Z1 = s(X1aX0_m_Y1aY0, a(X1mY1, X0mY0))
        Z0 = a(m(U, X1mY1), X0mY0)

        return Z1, Z0

    def inv(self, X: Fp2Ele) -> Fp2Ele:
        n = self._fp.neg
        s = self._fp.sub
        m = self._fp.mul

        X1, X0 = X
        U = -2

        UmX1mX1_s_X0mX0 = s(m(U, m(X1, X1)), m(X0, X0))
        invdet = self._fp.inv(UmX1mX1_s_X0mX0)

        Y1 = m(X1, invdet)
        Y0 = m(n(X0), invdet)

        return Y1, Y0

    def pow(self, X: Fp2Ele, e: int) -> Fp2Ele:
        Y = X
        for i in f"{e:b}"[1:]:
            Y = self.mul(Y, Y)
            if i == "1":
                Y = self.mul(Y, X)
        return Y

    def sqrt(self, X: Fp2Ele) -> Fp2Ele:
        raise NotImplementedError

    def etob(self, e: Fp2Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self._fp.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp2Ele:
        len_ = self._fp.e_length
        return tuple(self._fp.btoe(b[i:i+len_]) for i in range(0, len(b) - len_, len_))


class PrimeField4(PrimeFieldBase):
    """Fp4 operations."""

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele, Fp4Ele]) -> Fp4Ele:
        if isinstance(x, int) or len(x) < 4:
            return (PrimeField2.zero(), PrimeField2.extend(x))
        return x

    @classmethod
    def zero(cls) -> Fp4Ele:
        return (PrimeField2.zero(), PrimeField2.zero())

    @classmethod
    def one(cls) -> Fp4Ele:
        return (PrimeField2.zero(), PrimeField2.one())

    @classmethod
    def iszero(cls, X: Fp4Ele) -> bool:
        return all(PrimeField2.iszero(i) for i in X)

    @classmethod
    def isone(cls, X: Fp4Ele) -> bool:
        return all(PrimeField2.iszero(i) for i in X[:-1]) and PrimeField2.isone(X[-1])

    def __init__(self, p: int) -> None:
        self._fp2 = PrimeField2(p)
        self.e_length = self._fp2.e_length * 2

    def isoppo(self, X: Fp4Ele, Y: Fp4Ele) -> bool:
        return all(self._fp2.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp4Ele) -> Fp4Ele:
        return tuple(self._fp2.neg(i) for i in X)

    def sadd(self, n: int, x: Fp4Ele) -> Fp4Ele:
        x = list(x)
        x[-1] = self._fp2.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp4Ele) -> Fp4Ele:
        return tuple(self._fp2.smul(k, i) for i in x)

    def add(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        return tuple(self._fp2.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        return tuple(self._fp2.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        a = self._fp2.add
        s = self._fp2.sub
        m = self._fp2.mul

        X1, X0 = X
        Y1, Y0 = Y
        U = (1, 0)

        X1mY1 = m(X1, Y1)
        X0mY0 = m(X0, Y0)

        X1aX0_m_Y1aY0 = m(a(X1, X0), a(Y1, Y0))
        Z1 = s(X1aX0_m_Y1aY0, a(X1mY1, X0mY0))
        Z0 = a(m(U, X1mY1), X0mY0)

        return Z1, Z0

    def inv(self, X: Fp4Ele) -> Fp4Ele:
        n = self._fp2.neg
        s = self._fp2.sub
        m = self._fp2.mul

        X1, X0 = X
        U = (1, 0)

        UmX1mX1_s_X0mX0 = s(m(U, m(X1, X1)), m(X0, X0))
        invdet = self._fp2.inv(UmX1mX1_s_X0mX0)

        Y1 = m(X1, invdet)
        Y0 = m(n(X0), invdet)

        return Y1, Y0

    def pow(self, X: Fp4Ele, e: int) -> Fp4Ele:
        Y = X
        for i in f"{e:b}"[1:]:
            Y = self.mul(Y, Y)
            if i == "1":
                Y = self.mul(Y, X)
        return Y

    def sqrt(self, X: Fp4Ele) -> Fp4Ele:
        raise NotImplementedError

    def etob(self, e: Fp4Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self._fp2.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp4Ele:
        len_ = self._fp2.e_length
        return tuple(self._fp2.btoe(b[i:i+len_]) for i in range(0, len(b) - len_, len_))


class PrimeField12(PrimeField4):
    """Fp12 operations."""

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele, Fp4Ele, Fp12Ele]) -> Fp12Ele:
        if isinstance(x, int) or len(x) < 12:
            return (PrimeField4.zero(), PrimeField4.zero(), PrimeField4.extend(x))
        return x

    @classmethod
    def zero(cls) -> Fp12Ele:
        return (PrimeField4.zero(), PrimeField4.zero(), PrimeField4.zero())

    @classmethod
    def one(cls) -> Fp12Ele:
        return (PrimeField4.zero(), PrimeField4.zero(), PrimeField4.one())

    @classmethod
    def iszero(cls, X: Fp12Ele) -> bool:
        return all(PrimeField4.iszero(i) for i in X)

    @classmethod
    def isone(cls, X: Fp12Ele) -> bool:
        return all(PrimeField4.iszero(i) for i in X[:-1]) and PrimeField4.isone(X[-1])

    def __init__(self, p: int) -> None:
        self._fp4 = PrimeField4(p)
        self.e_length = self._fp4.e_length * 3

    def isoppo(self, X: Fp12Ele, Y: Fp12Ele) -> bool:
        return all(self._fp4.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp12Ele) -> Fp12Ele:
        return tuple(self._fp4.neg(i) for i in X)

    def sadd(self, n: int, x: Fp12Ele) -> Fp12Ele:
        x = list(x)
        x[-1] = self._fp4.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp12Ele) -> Fp12Ele:
        return tuple(self._fp4.smul(k, i) for i in x)

    def add(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        return tuple(self._fp4.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        return tuple(self._fp4.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        a = self._fp4.add
        s = self._fp4.sub
        m = self._fp4.mul

        X2, X1, X0 = X
        Y2, Y1, Y0 = Y
        U = ((0, 1), (0, 0))

        X2mY2, X1mY1, X0mY0 = m(X2, Y2), m(X1, Y1), m(X0, Y0)
        X2aX1, X2aX0, X1aX0 = a(X2, X1), a(X2, X0), a(X1, X0)
        Y2aY1, Y2aY0, Y1aY0 = a(Y2, Y1), a(Y2, Y0), a(Y1, Y0)

        X2aX1_m_Y2aY1 = m(X2aX1, Y2aY1)
        X2aX0_m_Y2aY0 = m(X2aX0, Y2aY0)
        X1aX0_m_Y1aY0 = m(X1aX0, Y1aY0)

        UmX2mY2 = m(U, X2mY2)
        X2mY1_a_X1Y2 = s(X2aX1_m_Y2aY1, a(X2mY2, X1mY1))

        Z2 = s(a(X2aX0_m_Y2aY0, X1mY1), a(X2mY2, X0mY0))
        Z1 = s(a(UmX2mY2, X1aX0_m_Y1aY0), a(X1mY1, X0mY0))
        Z0 = a(m(U, X2mY1_a_X1Y2), X0mY0)

        return Z2, Z1, Z0

    def inv(self, X: Fp12Ele) -> Fp12Ele:
        a = self._fp4.add
        s = self._fp4.sub
        m = self._fp4.mul

        X2, X1, X0 = X
        U = ((0, 1), (0, 0))

        UmX2 = m(U, X2)
        UmX1 = m(U, X1)

        X1mX1_s_X2mX0 = s(m(X1, X1), m(X2, X0))
        UmX2mX2_s_X1X0 = s(m(UmX2, X2), m(X1, X0))
        X0mX0_s_UmX2mX1 = s(m(X0, X0), m(UmX2, X1))

        det = a(m(UmX2, UmX2mX2_s_X1X0), a(m(UmX1, X1mX1_s_X2mX0), m(X0, X0mX0_s_UmX2mX1)))
        invdet = self._fp4.inv(det)

        Y2 = m(X1mX1_s_X2mX0, invdet)
        Y1 = m(UmX2mX2_s_X1X0, invdet)
        Y0 = m(X0mX0_s_UmX2mX1, invdet)

        return Y2, Y1, Y0

    def pow(self, X: Fp12Ele, e: int) -> Fp12Ele:
        Y = X
        for i in f"{e:b}"[1:]:
            Y = self.mul(Y, Y)
            if i == "1":
                Y = self.mul(Y, X)
        return Y

    def sqrt(self, X: Fp12Ele) -> Fp12Ele:
        raise NotImplementedError

    def etob(self, e: Fp12Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self._fp4.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp12Ele:
        len_ = self._fp4.e_length
        return tuple(self._fp4.btoe(b[i:i+len_]) for i in range(0, len(b) - len_, len_))
