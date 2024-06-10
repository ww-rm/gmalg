"""Prime field operations module.

This module provides basic operations on extension fields.
    The extension field is constructed through a tower extension in the "1-2-4-12" manner,
    as detailed in the SM9 standard documentation.
"""

from typing import Tuple, Union

from .errors import *

__all__ = [
    "Fp2Ele",
    "Fp4Ele",
    "Fp12Ele",
    "FpExEle",
    "PrimeFieldBase",
    "PrimeField",
    "PrimeField2",
    "PrimeField4",
    "PrimeField12",
]

# towering method: 1-2-4-12
# (  11, 10,    9,  8,      7,  6,    5,  4,      3,  2,    1,  0  )
# (((11,  5), ( 8,  2)), ((10,  4), ( 7,  1)), (( 9,  3), ( 6,  0)))

Fp2Ele = Tuple[int, int]
Fp4Ele = Tuple[Fp2Ele, Fp2Ele]
Fp12Ele = Tuple[Fp4Ele, Fp4Ele, Fp4Ele]
FpExEle = Union[int, Fp2Ele, Fp4Ele, Fp12Ele]


class PrimeFieldBase:
    """Base class of Fp operations.

    All subclasses derived from this class have the same methods as the base class,
        with the only difference being the replacement of the type `FpExEle` with the corresponding field element type.

    Any variations will be explicitly documented within the respective subclass.
    """

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
        """Extend domain element."""

        raise NotImplementedError

    def __init__(self, p: int) -> None:
        """Base class of Fp operations.

        Args:
            p: A prime number.
        """

        raise NotImplementedError

    def isoppo(self, x: FpExEle, y: FpExEle) -> bool:
        """Whether is opposite."""

        raise NotImplementedError

    def neg(self, x: FpExEle) -> FpExEle:
        """Negative."""

        raise NotImplementedError

    def sadd(self, n: int, x: FpExEle) -> FpExEle:
        """Scalar add."""

        raise NotImplementedError

    def smul(self, k: int, x: FpExEle) -> FpExEle:
        """Scalar mul."""

        raise NotImplementedError

    def pmul(self, x: FpExEle, y: FpExEle) -> FpExEle:
        """Multiply by position."""

        raise NotImplementedError

    def add(self, x: FpExEle, y: FpExEle) -> FpExEle:
        """Add two elements."""

        raise NotImplementedError

    def sub(self, x: FpExEle, y: FpExEle) -> FpExEle:
        """Substract two elements."""

        raise NotImplementedError

    def mul(self, x: FpExEle, y: FpExEle) -> FpExEle:
        """Multiply two elements."""

        raise NotImplementedError

    def inv(self, x: FpExEle) -> FpExEle:
        """Inverse of element."""

        raise NotImplementedError

    def pow(self, x: FpExEle, e: int) -> FpExEle:
        """Get the exponentiation of x raised to the power of e."""

        raise NotImplementedError

    def sqrt(self, x: FpExEle) -> Union[FpExEle, None]:
        """Square root of x."""

        raise NotImplementedError

    def etob(self, e: FpExEle) -> bytes:
        """Convert domain element to bytes."""

        raise NotImplementedError

    def btoe(self, b: bytes) -> FpExEle:
        """Convert bytes to domain element."""

        raise NotImplementedError


class PrimeField(PrimeFieldBase):
    """Fp operations.

    Attributes:
        p (int): Prime number used in operations.
        p_bitlength (int): Bit length of p.
        p_length (int): Byte length of p.
        e_length (int): Byte length of domain element.
    """

    _ZERO = 0
    _ONE = 1

    @classmethod
    def zero(cls) -> int:
        return cls._ZERO

    @classmethod
    def one(cls) -> int:
        return cls._ONE

    @classmethod
    def iszero(cls, x: int) -> bool:
        return x == cls._ZERO

    @classmethod
    def isone(cls, x: int) -> bool:
        return x == cls._ONE

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
            raise InvalidArgumentError(f"0x{p:x} is not a prime number.")

    def isoppo(self, x: int, y: int) -> bool:
        return x == 0 and y == 0 or x + y == self.p

    def neg(self, x: int) -> int:
        return (-x) % self.p

    def sadd(self, n: int, x: int) -> int:
        return (n + x) % self.p

    def smul(self, k: int, x: int) -> int:
        return (k * x) % self.p

    def pmul(self, x: int, y: int) -> int:
        return (x * y) % self.p

    def add(self, x: int, y: int) -> int:
        return (x + y) % self.p

    def sub(self, x: int, y: int) -> int:
        return (x - y) % self.p

    def mul(self, x: int, y: int) -> int:
        return (x * y) % self.p

    def inv(self, x: int):
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
        """Lucas sequence, k begin at 0.

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

    def _sqrt_4u3(self, x: int) -> Union[int, None]:
        """sqrt_8u3 and sqrt_8u7"""
        p = self.p
        u = self._u

        y = pow(x, u + 1, p)
        if (y * y) % p == x:
            return y
        return None

    def _sqrt_8u5(self, x: int) -> Union[int, None]:
        p = self.p
        u = self._u

        z = pow(x, 2 * u + 1, p)
        if z == 1:
            return pow(x, u + 1, p)
        if z == p - 1:
            return (2 * x * pow(4 * x, u, p)) % p
        return None

    def _sqrt_8u1(self, x: int) -> Union[int, None]:
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
                return None

        return None

    def sqrt(self, x: int) -> Union[int, None]:
        raise NotImplementedError

    def etob(self, e: int) -> bytes:
        return e.to_bytes(self.e_length, "big")

    def btoe(self, b: bytes) -> int:
        return int.from_bytes(b, "big")


class PrimeField2(PrimeFieldBase):
    """Fp2 operations.

    Attributes:
        fp (PrimeField): `PrimeField` used in operations.
        e_length (int): Byte length of domain element.
    """

    _ALPHA: int = -2

    _ZERO = (PrimeField.zero(), PrimeField.zero())
    _ONE = (PrimeField.zero(), PrimeField.one())

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele]) -> Fp2Ele:
        if isinstance(x, int):
            return (PrimeField.zero(), x)
        return x

    @classmethod
    def zero(cls) -> Fp2Ele:
        return cls._ZERO

    @classmethod
    def one(cls) -> Fp2Ele:
        return cls._ONE

    @classmethod
    def iszero(cls, X: Fp2Ele) -> bool:
        return X == cls._ZERO

    @classmethod
    def isone(cls, X: Fp2Ele) -> bool:
        return X == cls._ONE

    def __init__(self, p: int) -> None:
        self.fp = PrimeField(p)
        self.e_length = self.fp.e_length * 2

    def isoppo(self, X: Fp2Ele, Y: Fp2Ele) -> bool:
        return all(self.fp.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp2Ele) -> Fp2Ele:
        return tuple(self.fp.neg(i) for i in X)

    def sadd(self, n: int, x: Fp2Ele) -> Fp2Ele:
        x = list(x)
        x[-1] = self.fp.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp2Ele) -> Fp2Ele:
        return tuple(self.fp.smul(k, i) for i in x)

    def pmul(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        return tuple(self.fp.pmul(i1, i2) for i1, i2 in zip(X, Y))

    def add(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        return tuple(self.fp.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        return tuple(self.fp.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp2Ele, Y: Fp2Ele) -> Fp2Ele:
        a = self.fp.add
        s = self.fp.sub
        m = self.fp.mul

        X1, X0 = X
        Y1, Y0 = Y
        U = self._ALPHA

        X1mY1 = m(X1, Y1)
        X0mY0 = m(X0, Y0)

        X1aX0_m_Y1aY0 = m(a(X1, X0), a(Y1, Y0))
        Z1 = s(X1aX0_m_Y1aY0, a(X1mY1, X0mY0))
        Z0 = a(m(U, X1mY1), X0mY0)

        return Z1, Z0

    def inv(self, X: Fp2Ele) -> Fp2Ele:
        n = self.fp.neg
        s = self.fp.sub
        m = self.fp.mul

        X1, X0 = X
        U = self._ALPHA

        UmX1mX1_s_X0mX0 = s(m(U, m(X1, X1)), m(X0, X0))
        invdet = self.fp.inv(UmX1mX1_s_X0mX0)

        Y1 = m(X1, invdet)
        Y0 = m(n(X0), invdet)

        return Y1, Y0

    def conj(self, X: Fp2Ele) -> Fp2Ele:
        x1, x0 = X
        return (self.fp.neg(x1), x0)

    def pow(self, X: Fp2Ele, e: int) -> Fp2Ele:
        Y = X
        for i in f"{e:b}"[1:]:
            Y = self.mul(Y, Y)
            if i == "1":
                Y = self.mul(Y, X)
        return Y

    def sqrt(self, X: Fp2Ele) -> Union[Fp2Ele, None]:
        n = self.fp.neg
        a = self.fp.add
        s = self.fp.sub
        m = self.fp.mul

        X1, X0 = X
        U = s(m(X0, X0), m(self._ALPHA, m(X1, X1)))

        w1 = self.fp.sqrt(U)
        if w1 is None:
            return None

        w2 = n(w1)
        i2 = self.fp.inv(2)

        for w in (w1, w2):
            V = m(a(X0, w), i2)
            y = self.fp.sqrt(V)
            if y is None:
                continue

            Y1 = m(X1, self.fp.inv(m(2, y)))
            Y0 = y

            return Y1, Y0

        return None

    def etob(self, e: Fp2Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self.fp.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp2Ele:
        len_ = self.fp.e_length
        return tuple(self.fp.btoe(b[i:i+len_]) for i in range(0, len(b), len_))


class PrimeField4(PrimeFieldBase):
    """Fp4 operations.

    Attributes:
        fp2 (PrimeField2): `PrimeField2` used in operations.
        e_length (int): Byte length of domain element.
    """

    _ALPHA: Fp2Ele = (1, 0)
    _ZERO = (PrimeField2.zero(), PrimeField2.zero())
    _ONE = (PrimeField2.zero(), PrimeField2.one())

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele, Fp4Ele]) -> Fp4Ele:
        if isinstance(x, int):
            return (PrimeField2.zero(), (PrimeField.zero(), x))
        elif isinstance(x[0], int):
            return (PrimeField2.zero(), x)
        return x

    @classmethod
    def zero(cls) -> Fp4Ele:
        return cls._ZERO

    @classmethod
    def one(cls) -> Fp4Ele:
        return cls._ONE

    @classmethod
    def iszero(cls, X: Fp4Ele) -> bool:
        return X == cls._ZERO

    @classmethod
    def isone(cls, X: Fp4Ele) -> bool:
        return X == cls._ONE

    def __init__(self, p: int) -> None:
        self.fp2 = PrimeField2(p)
        self.e_length = self.fp2.e_length * 2

    def isoppo(self, X: Fp4Ele, Y: Fp4Ele) -> bool:
        return all(self.fp2.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp4Ele) -> Fp4Ele:
        return tuple(self.fp2.neg(i) for i in X)

    def sadd(self, n: int, x: Fp4Ele) -> Fp4Ele:
        x = list(x)
        x[-1] = self.fp2.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp4Ele) -> Fp4Ele:
        return tuple(self.fp2.smul(k, i) for i in x)

    def pmul(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        return tuple(self.fp2.pmul(i1, i2) for i1, i2 in zip(X, Y))

    def add(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        return tuple(self.fp2.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        return tuple(self.fp2.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp4Ele, Y: Fp4Ele) -> Fp4Ele:
        a = self.fp2.add
        s = self.fp2.sub
        m = self.fp2.mul

        X1, X0 = X
        Y1, Y0 = Y
        U = self._ALPHA

        X1mY1 = m(X1, Y1)
        X0mY0 = m(X0, Y0)

        X1aX0_m_Y1aY0 = m(a(X1, X0), a(Y1, Y0))
        Z1 = s(X1aX0_m_Y1aY0, a(X1mY1, X0mY0))
        Z0 = a(m(U, X1mY1), X0mY0)

        return Z1, Z0

    def inv(self, X: Fp4Ele) -> Fp4Ele:
        n = self.fp2.neg
        s = self.fp2.sub
        m = self.fp2.mul

        X1, X0 = X
        U = self._ALPHA

        UmX1mX1_s_X0mX0 = s(m(U, m(X1, X1)), m(X0, X0))
        invdet = self.fp2.inv(UmX1mX1_s_X0mX0)

        Y1 = m(X1, invdet)
        Y0 = m(n(X0), invdet)

        return Y1, Y0

    def conj(self, X: Fp4Ele) -> Fp4Ele:
        X1, X0 = X
        return (self.fp2.neg(X1), X0)

    def pow(self, X: Fp4Ele, e: int) -> Fp4Ele:
        Y = X
        for i in f"{e:b}"[1:]:
            Y = self.mul(Y, Y)
            if i == "1":
                Y = self.mul(Y, X)
        return Y

    def sqrt(self, X: Fp4Ele) -> Union[Fp4Ele, None]:
        raise NotImplementedError

    def etob(self, e: Fp4Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self.fp2.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp4Ele:
        len_ = self.fp2.e_length
        return tuple(self.fp2.btoe(b[i:i+len_]) for i in range(0, len(b), len_))


class PrimeField12(PrimeFieldBase):
    """Fp12 operations.

    Attributes:
        fp4 (PrimeField4): `PrimeField4` used in operations.
        e_length (int): Byte length of domain element.
    """

    _ALPHA: Fp4Ele = ((0, 1), (0, 0))
    _ZERO = (PrimeField4.zero(), PrimeField4.zero(), PrimeField4.zero())
    _ONE = (PrimeField4.zero(), PrimeField4.zero(), PrimeField4.one())

    @classmethod
    def extend(cls, x: Union[int, Fp2Ele, Fp4Ele, Fp12Ele]) -> Fp12Ele:
        if isinstance(x, int):
            return (PrimeField4.zero(), PrimeField4.zero(), (PrimeField2.zero(), (PrimeField.zero(), x)))
        elif isinstance(x[0], int):
            return (PrimeField4.zero(), PrimeField4.zero(), (PrimeField2.zero(), x))
        elif isinstance(x[0][0], int):
            return (PrimeField4.zero(), PrimeField4.zero(), x)
        return x

    @classmethod
    def zero(cls) -> Fp12Ele:
        return cls._ZERO

    @classmethod
    def one(cls) -> Fp12Ele:
        return cls._ONE

    @classmethod
    def iszero(cls, X: Fp12Ele) -> bool:
        return X == cls._ZERO

    @classmethod
    def isone(cls, X: Fp12Ele) -> bool:
        return X == cls._ONE

    def __init__(self, p: int) -> None:
        self.fp4 = PrimeField4(p)
        self.e_length = self.fp4.e_length * 3

    def isoppo(self, X: Fp12Ele, Y: Fp12Ele) -> bool:
        return all(self.fp4.isoppo(i1, i2) for i1, i2 in zip(X, Y))

    def neg(self, X: Fp12Ele) -> Fp12Ele:
        return tuple(self.fp4.neg(i) for i in X)

    def sadd(self, n: int, x: Fp12Ele) -> Fp12Ele:
        x = list(x)
        x[-1] = self.fp4.sadd(n, x[-1])
        return tuple(x)

    def smul(self, k: int, x: Fp12Ele) -> Fp12Ele:
        return tuple(self.fp4.smul(k, i) for i in x)

    def pmul(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        return tuple(self.fp4.pmul(i1, i2) for i1, i2 in zip(X, Y))

    def add(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        return tuple(self.fp4.add(i1, i2) for i1, i2 in zip(X, Y))

    def sub(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        return tuple(self.fp4.sub(i1, i2) for i1, i2 in zip(X, Y))

    def mul(self, X: Fp12Ele, Y: Fp12Ele) -> Fp12Ele:
        a = self.fp4.add
        s = self.fp4.sub
        m = self.fp4.mul

        X2, X1, X0 = X
        Y2, Y1, Y0 = Y
        U = self._ALPHA

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
        a = self.fp4.add
        s = self.fp4.sub
        m = self.fp4.mul

        X2, X1, X0 = X
        U = self._ALPHA

        UmX2 = m(U, X2)
        UmX1 = m(U, X1)

        X1mX1_s_X2mX0 = s(m(X1, X1), m(X2, X0))
        UmX2mX2_s_X1X0 = s(m(UmX2, X2), m(X1, X0))
        X0mX0_s_UmX2mX1 = s(m(X0, X0), m(UmX2, X1))

        det = a(m(UmX2, UmX2mX2_s_X1X0), a(m(UmX1, X1mX1_s_X2mX0), m(X0, X0mX0_s_UmX2mX1)))
        invdet = self.fp4.inv(det)

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

    def sqrt(self, X: Fp12Ele) -> Union[Fp12Ele, None]:
        raise NotImplementedError

    def etob(self, e: Fp12Ele) -> bytes:
        b = bytearray()
        for i in e:
            b.extend(self.fp4.etob(i))
        return bytes(b)

    def btoe(self, b: bytes) -> Fp12Ele:
        len_ = self.fp4.e_length
        return tuple(self.fp4.btoe(b[i:i+len_]) for i in range(0, len(b), len_))
