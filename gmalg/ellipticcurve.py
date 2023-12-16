"""Elliptic curve operations.

This module provides fundamental operations related to elliptic curves,
    including but not limited to those specified in the national cryptographic standard documents.

For convenience, the module defines the following custom types related to elliptic curve points:

```python
EcPoint = Tuple[int, int]
EcPoint2 = Tuple[Fp2Ele, Fp2Ele]
EcPoint4 = Tuple[Fp4Ele, Fp4Ele]
EcPoint12 = Tuple[Fp12Ele, Fp12Ele]
EcPointEx = Tuple[FpExEle, FpExEle]
```

These data types align with extension field element types and are used by the module to perform operations on elliptic curves.
"""

from typing import Tuple, Union

from . import errors
from . import primefield as Fp

__all__ = [
    "EcPoint",
    "EcPoint2",
    "EcPoint4",
    "EcPoint12",
    "EcPointEx",
    "EllipticCurve",
    "ECDLP",
    "SM9BNBP",
]

EcPoint = Tuple[int, int]
EcPoint2 = Tuple[Fp.Fp2Ele, Fp.Fp2Ele]
EcPoint4 = Tuple[Fp.Fp4Ele, Fp.Fp4Ele]
EcPoint12 = Tuple[Fp.Fp12Ele, Fp.Fp12Ele]
EcPointEx = Tuple[Fp.FpExEle, Fp.FpExEle]


class EllipticCurve:
    """Elliptic Curve.

    Attributes:
        INF: Infinite point.
        a (FpExEle): Parameter a of curve.
        b (FpExEle): Parameter b of curve.
    """

    INF: EcPointEx = (float("inf"), float("inf"))

    def __init__(self, fp: Fp.PrimeFieldBase, a: Fp.FpExEle, b: Fp.FpExEle) -> None:
        """Elliptic curve.

        Args:
            fp (PrimeFieldBase): Prime field operations used in ellitic curve, must be derived from class `PrimeFieldBase`. 
            a (FpExEle): Parameter a of curve.
            b (FpExEle): Parameter b of curve.

        Note:
            When instantiating the class, the `FpExEle` or `EcPointEx` type in the methods will correspond to the type of `fp`.
                Here, a generic placeholder are used to denote the data type.
        """

        self.a = a
        self.b = b
        self._fp = fp

    def get_y_sqr(self, x: Fp.FpExEle) -> Fp.FpExEle:
        """Get the square of y for the specified x."""

        fp = self._fp
        return fp.add(fp.pow(x, 3), fp.add(fp.mul(self.a, x), self.b))

    def get_y(self, x: Fp.FpExEle) -> Union[Fp.FpExEle, None]:
        """Get one of valid y for given x, `None` means no solution."""

        return self._fp.sqrt(self.get_y_sqr(x))

    def isvalid(self, P: EcPointEx) -> bool:
        """Whether the point is on curve."""

        x, y = P
        return self._fp.mul(y, y) == self.get_y_sqr(x)

    def neg(self, P: EcPointEx) -> EcPointEx:
        """Get negative point."""

        x, y = P
        return (x, self._fp.neg(y))

    def add(self, P1: EcPointEx, P2: EcPointEx) -> EcPointEx:
        """Add two points."""

        fp = self._fp

        if P1 == self.INF:
            return P2
        if P2 == self.INF:
            return P1

        x1, y1 = P1
        x2, y2 = P2

        if x1 == x2:
            if fp.isoppo(y1, y2):
                return self.INF
            elif y1 == y2:
                _t1 = fp.add(self.a, fp.smul(3, fp.mul(x1, x1)))
                _t2 = fp.inv(fp.smul(2, y1))
                lam = fp.mul(_t1, _t2)
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam = fp.mul(fp.sub(y2, y1), fp.inv(fp.sub(x2, x1)))

        x3 = fp.sub(fp.mul(lam, lam), fp.add(x1, x2))
        y3 = fp.sub(fp.mul(lam, fp.sub(x1, x3)), y1)
        return x3, y3

    def sub(self, P1: EcPointEx, P2: EcPointEx) -> EcPointEx:
        """Substract two points."""

        return self.add(P1, self.neg(P2))

    def mul(self, k: int, P: EcPointEx) -> EcPointEx:
        """Scalar multiplication of point by k."""

        Q = P
        for i in f"{k:b}"[1:]:
            Q = self.add(Q, Q)
            if i == "1":
                Q = self.add(Q, P)
        return Q


class ECDLP:
    """Elliptic Curve Discrete Logarithm Problem.

    Attributes:
        fp (PrimeField): `PrimeField` used in ECDLP.
        ec (EllipticCurve): `EllipticCurve` used in ECDLP.
        G (EcPoint): Base point.
        fpn (PrimeField): `PrimeField` operations for the order of base point.
        h (int): Cofactor of base point.
    """

    def __init__(self, p: int, a: int, b: int, G: EcPoint, n: int, h: int = 1) -> None:
        """Elliptic Curve Discrete Logarithm Problem.

        Args:
            p (int): Parameter p of curve.
            a (int): Parameter a of curve.
            b (int): Parameter b of curve.
            G (EcPoint): Base point.
            n (int): Order of base point.
            h (int): Cofactor of `G`, default to `1`.
        """

        self.fp = Fp.PrimeField(p)
        self.ec = EllipticCurve(self.fp, a, b)
        self.G = G
        self.fpn = Fp.PrimeField(n)
        self.h = h

    def kG(self, k: int) -> EcPoint:
        """Scalar multiplication of G by k."""

        return self.ec.mul(k, self.G)


class SM9BNBP:
    """SM9 Bilinear Pairing on Barreto-Naehrig (BN) Elliptic Curve.

    For performance reasons,
        this implementation focuses solely on operations on the BN curve in the context of SM9.
        Consequently, certain intermediate values can be precomputed to enhance computational efficiency.

    The fundamental parameters used in SM9 are as follows:

    ```python
    t = 0x600000000058F98A
    p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
    n = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
    b = 0x05
    beta_b = (5, 0)
    ```

    There are some more precomputed intermediate values.
        Refer to the source code for detailed information.

    Attributes:
        t (int): Parameter t of SM9.
        fp12 (PrimeField12): `PrimeField12` operations used in SM9.
        fp2 (PrimeField2): `PrimeField2` operations used in SM9.
        fp1 (PrimeField): `PrimeField` operations used in SM9.
        fpn (PrimeField): `PrimeField` operations for the order of base point.
        ec1 (EllipticCurve): `EllipticCurve` on Fp operations used in SM9.
        ec2 (EllipticCurve): `EllipticCurve` on Fp2 operations used in SM9.
        G1 (EcPoint): Base point of group 1.
        G2 (EcPoint2): Base point of group 2.
    """

    def __init__(self, G1: EcPoint, G2: EcPoint2) -> None:
        """SM9 Bilinear Pairing on Barreto-Naehrig (BN) Elliptic Curve.

        Args:
            G1 (EcPoint): Base point of group 1.
            G2 (EcPoint2): Base point of group 2.
        """

        # SM9 parameters

        t = 0x600000000058F98A
        p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D  # 36 * t**4 + 36 * t**3 + 24 * t**2 + 6 * t + 1
        n = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25  # 36 * t**4 + 36 * t**3 + 18 * t**2 + 6 * t + 1
        b = 0x05
        beta_b = (5, 0)  # (1, 0) * (0, 5)

        self.t = t

        self.fp12 = Fp.PrimeField12(p)
        self.fp2 = self.fp12.fp4.fp2
        self.fp1 = self.fp2.fp
        self.fpn = Fp.PrimeField(n)

        self.ec1 = EllipticCurve(self.fp1, 0, b)
        self.ec2 = EllipticCurve(self.fp2, (0, 0), beta_b)

        self.G1 = G1
        self.G2 = G2

        # self._a = 0x2400000000215D93E  # 6 * t + 2
        self._e_a = "00100000000000000000000000000000000000010000101011101100100111110"  # f"{self._a:b}"[1:]

        # phi factors

        self._neg2 = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457B  # self.fp1.neg(2)
        self._inv_neg2 = 0x5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2BE  # self.fp1.inv(self._neg2)

        # Frobenius factors

        w5 = 0x2D40A38CF6983351711E5F99520347CC57D778A9F8FF4C8A4C949C7FA2A96686
        w4 = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65333
        w3 = 0x6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011
        w2 = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65334
        w1 = 0x3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B
        w0 = 0x1

        self._frob1_factor = (((p - w5, w5), (p - w2, w2)), ((p - w4, w4), (p - w1, w1)), ((p - w3, w3), (p - w0, w0)))
        self._frob2_factor = (((p - w4, p - w4), (w4, w4)), ((p - w2, p - w2), (w2, w2)), ((p - w0, p - w0), (w0, w0)))
        self._frob3_factor = (((p - w3, w3), (w0, p - w0)), ((p - w0, w0), (p - w3, w3)), ((w3, p - w3), (p - w0, w0)))
        self._frob6_factor = (((p - w0, p - w0), (w0, w0)), ((w0, w0), (p - w0, p - w0)), ((p - w0, p - w0), (w0, w0)))

    def kG1(self, k: int) -> EcPoint:
        """Scalar multiplication of G1 by k."""

        return self.ec1.mul(k, self.G1)

    def kG2(self, k: int) -> EcPoint2:
        """Scalar multiplication of G2 by k."""

        return self.ec2.mul(k, self.G2)

    def _g_fn(self, U: EcPoint12, V: EcPoint12, Q: EcPoint12) -> Fp.Fp12Ele:
        """g(U, V)(Q).

        U, V, Q are Fp12 points.
        """

        fp12 = self.fp12

        if U == EllipticCurve.INF or V == EllipticCurve.INF or Q == EllipticCurve.INF:
            return fp12.one()

        xU, yU = U
        xV, yV = V
        xQ, yQ = Q

        if xU == xV:
            if fp12.isoppo(yU, yV):
                return fp12.sub(xQ, xV), fp12.one()
            elif yU == yV:
                lam = fp12.mul(
                    fp12.smul(3, fp12.mul(xV, xV)),
                    fp12.inv(fp12.smul(2, yV))
                )
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam = fp12.mul(fp12.sub(yU, yV), fp12.inv(fp12.sub(xU, xV)))

        g = fp12.sub(fp12.mul(lam, fp12.sub(xQ, xV)), fp12.sub(yQ, yV))
        return g

    def _phi(self, P: EcPoint2) -> EcPoint12:
        """Get x, y in E (Fp12) from E' (Fp2), only implemented for beta=(1, 0)."""

        fp1 = self.fp1
        _i2 = self._inv_neg2

        x_, y_ = P

        x: Fp.Fp12Ele = (((0, 0), (0, 0)), ((fp1.mul(x_[1], _i2), x_[0]), (0, 0)), ((0, 0), (0, 0)))
        y: Fp.Fp12Ele = (((0, 0), (0, 0)), ((0, 0), (0, 0)), ((fp1.mul(y_[1], _i2), y_[0]), (0, 0)))

        return x, y

    def _phi_inv(self, P: EcPoint12) -> EcPoint2:
        """Inversion of `phi`."""

        fp1 = self.fp1
        _2 = self._neg2

        x_, y_ = P

        x: Fp.Fp2Ele = (x_[1][0][1], fp1.mul(x_[1][0][0], _2))
        y: Fp.Fp2Ele = (y_[2][0][1], fp1.mul(y_[2][0][0], _2))

        return x, y

    def _frob1(self, X: Fp.Fp12Ele) -> Fp.Fp12Ele:
        return self.fp12.pmul(X, self._frob1_factor)

    def _frob2(self, X: Fp.Fp12Ele) -> Fp.Fp12Ele:
        return self.fp12.pmul(X, self._frob2_factor)

    def _frob3(self, X: Fp.Fp12Ele) -> Fp.Fp12Ele:
        return self.fp12.pmul(X, self._frob3_factor)

    def _frob6(self, X: Fp.Fp12Ele) -> Fp.Fp12Ele:
        fp4 = self.fp12.fp4
        X2, X1, X0 = X
        return (fp4.conj(X2), fp4.neg(fp4.conj(X1)), fp4.conj(X0))

    def _finalexp(self, f: Fp.Fp12Ele) -> Fp.Fp12Ele:
        fp12 = self.fp12
        M = fp12.mul
        I = fp12.inv
        P = fp12.pow
        F1 = self._frob1
        F2 = self._frob2
        F3 = self._frob3
        F6 = self._frob6

        # easy part
        f = M(F6(f), I(f))
        f = M(F2(f), f)

        # hard part
        f_t = P(f, self.t)
        f_t2 = P(f_t, self.t)
        f_t3 = P(f_t2, self.t)

        f_p = F1(f)
        f_p2 = F2(f)
        f_p3 = F3(f)

        f_t_p = F1(f_t)
        f_t2_p = F1(f_t2)
        f_t3_p = F1(f_t3)
        f_t2_p2 = F2(f_t2)

        # y6, y5, y4, y3, y2, y1, y0
        #  -,  -,  -,  -,  +,  -,  +
        y6 = P(M(f_t3, f_t3_p), 36)
        y5 = P(f_t2, 30)
        y4 = P(M(f_t2_p, f_t), 18)
        y3 = P(f_t_p, 12)
        y2 = P(f_t2_p2, 6)
        y1 = M(f, f)
        y0 = M(f_p, M(f_p2, f_p3))

        f_num = M(y2, y0)
        f_den = M(y6, M(y5, M(y4, M(y3, y1))))

        f = M(f_num, I(f_den))
        return f

    def e(self, P: EcPoint, Q: EcPoint2) -> Fp.Fp12Ele:
        """R-ate bilinear pairing.

        Args:
            P (EcPoint): Element of group 1.
            Q (EcPoint2): Element of group 2.

        Returns:
            Fp12Ele: Pairing value on Fp12.
        """

        fp12 = self.fp12
        ec2 = self.ec2
        phi = self._phi
        g_fn = self._g_fn

        _P = (fp12.extend(P[0]), fp12.extend(P[1]))  # P on E(Fp12)
        _Q = phi(Q)  # Q on E(Fp12)

        T = Q
        f = fp12.one()
        for i in self._e_a:
            _T = phi(T)  # T on E(Fp12)
            g = g_fn(_T, _T, _P)
            f = fp12.mul(fp12.mul(f, f), g)
            T = ec2.add(T, T)

            if i == "1":
                g = g_fn(phi(T), _Q, _P)
                f = fp12.mul(f, g)
                T = ec2.add(T, Q)

        _Q1 = (self._frob1(_Q[0]), self._frob1(_Q[1]))
        _Q2 = (self._frob2(_Q[0]), fp12.neg(self._frob2(_Q[1])))

        g = g_fn(phi(T), _Q1, _P)
        f = fp12.mul(f, g)

        T = ec2.add(T, self._phi_inv(_Q1))

        g = g_fn(phi(T), _Q2, _P)
        f = fp12.mul(f, g)

        f = self._finalexp(f)
        return f

    def eG1(self, Q: EcPoint2) -> Fp.Fp12Ele:
        """R-ate of G1 and Q."""

        return self.e(self.G1, Q)

    def eG2(self, P: EcPoint) -> Fp.Fp12Ele:
        """R-ate of P and G2."""

        return self.e(P, self.G2)
