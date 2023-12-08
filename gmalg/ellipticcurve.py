from typing import Tuple

from . import errors
from . import primefield as Fp

EcPoint = Tuple[Fp.FpExEle, Fp.FpExEle]


class EllipticCurve:
    """Elliptic Curve (Fp)"""

    INF: EcPoint = (float("inf"), float("inf"))

    def __init__(self, fp: Fp.PrimeFieldBase, a: Fp.FpExEle, b: Fp.FpExEle) -> None:
        self.a = a
        self.b = b
        self._fp = fp

    def get_y_sqr(self, x: Fp.FpExEle) -> Fp.FpExEle:
        fp = self._fp
        return fp.add(fp.pow(x, 3), fp.add(fp.mul(self.a, x), self.b))

    def get_y(self, x: int) -> int:
        """Get one of valid y of given x, -1 means no solution."""
        return self._fp.sqrt(self.get_y_sqr(x))

    def isvalid(self, P: EcPoint) -> bool:
        x, y = P
        return self._fp.mul(y, y) == self.get_y_sqr(x)

    def neg(self, P: EcPoint) -> EcPoint:
        x, y = P
        return (x, self._fp.neg(y))

    def add(self, P1: EcPoint, P2: EcPoint) -> EcPoint:
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

    def sub(self, P1: EcPoint, P2: EcPoint) -> EcPoint:
        return self.add(P1, self.neg(P2))

    def mul(self, k: int, P: EcPoint) -> EcPoint:
        Q = P
        for i in f"{k:b}"[1:]:
            Q = self.add(Q, Q)
            if i == "1":
                Q = self.add(Q, P)
        return Q


class ECDLP:
    """Elliptic Curve Discrete Logarithm Problem"""

    def __init__(self, p: int, a: int, b: int, G: EcPoint, n: int, h: int = 1) -> None:
        """Elliptic Curve Discrete Logarithm Problem

        Elliptic Curve (Fp): y^2 = x^3 + ax + b (mod p)

        Base point: G
        Order of the base point: n
        Cofactor: h
        """

        self.fp = Fp.PrimeField(p)
        self.ec = EllipticCurve(self.fp, a, b)
        self.G = G
        self.fpn = Fp.PrimeField(n)
        self.h = h

    def kG(self, k: int) -> EcPoint:
        """Scalar multiplication of G by k."""

        return self.ec.mul(k, self.G)

    def etob(self, e: int) -> bytes:
        return self.fp.etob(e)

    def btoe(self, b: bytes) -> int:
        return self.fp.btoe(b)


class BNBIDH:
    """BN Elliptic Curve Bilinear Inverse Diffie-Hellman."""

    def __init__(self, t: int, b: int, beta: Fp.Fp2Ele, G1: EcPoint, G2: EcPoint) -> None:
        """BN Elliptic Curve Bilinear Inverse Diffie-Hellman.

        Args:
            t (int): t.
            b (int): param b of elliptic curve.
            beta (Fp2Ele): param beta of twin curve, must be (1, 0)
            G1 (EcPoint): Base point of group 1.
            G2 (EcPoint): Base point of group 2.
        """

        if beta != (1, 0):
            raise NotImplementedError(f"beta: {beta}")

        self.t = t
        self.p = 36 * t**4 + 36 * t**3 + 24 * t**2 + 6 * t + 1
        self.n = 36 * t**4 + 36 * t**3 + 18 * t**2 + 6 * t + 1

        self.fpk = Fp.PrimeField12(self.p)
        self.fp1 = Fp.PrimeField(self.p)
        self.fp2 = Fp.PrimeField2(self.p)

        self.ec2 = EllipticCurve(self.fp2, self.fp2.zero(), self.fp2.mul(beta, self.fp2.extend(b)))

        self.G1 = G1
        self.G2 = G2

        self._a = 6 * t + 2

        self._neg2 = self.fp1.neg(2)
        self._inv_neg2 = self.fp1.inv(self._neg2)

        self._p2 = self.p * self.p
        self._fexp = (self.p ** 12 - 1) // self.n

    def _g_fn(self, U: EcPoint, V: EcPoint, Q: EcPoint) -> Tuple[Fp.Fp12Ele, Fp.Fp12Ele]:
        """g(U, V)(Q). U, V, Q are Fp12 points."""

        fpk = self.fpk

        if U == EllipticCurve.INF or V == EllipticCurve.INF or Q == EllipticCurve.INF:
            return fpk.one()

        xU, yU = U
        xV, yV = V
        xQ, yQ = Q

        if xU == xV:
            if fpk.isoppo(yU, yV):
                return fpk.sub(xQ, xV), fpk.one()
            elif yU == yV:
                lam1 = fpk.smul(3, fpk.mul(xV, xV))
                lam2 = fpk.smul(2, yV)
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam1 = fpk.sub(yU, yV)
            lam2 = fpk.sub(xU, xV)

        g1 = fpk.sub(fpk.mul(lam1, fpk.sub(xQ, xV)), fpk.mul(lam2, fpk.sub(yQ, yV)))
        g2 = lam2
        return g1, g2

    def _phi(self, P: EcPoint) -> EcPoint:
        """Get x, y in E (Fp12) from E' (Fp2), only implemented for beta=(1, 0)"""

        fp1 = self.fp1
        _i2 = self._inv_neg2

        x_, y_ = P

        x: Fp.Fp12Ele = (((0, 0), (0, 0)), ((fp1.mul(x_[1], _i2), x_[0]), (0, 0)), ((0, 0), (0, 0)))
        y: Fp.Fp12Ele = (((0, 0), (0, 0)), ((0, 0), (0, 0)), ((fp1.mul(y_[1], _i2), y_[0]), (0, 0)))

        return x, y

    def _phi_inv(self, P: EcPoint) -> EcPoint:
        """Inversion of phi."""

        fp1 = self.fp1
        _2 = self._neg2

        x_, y_ = P

        x: Fp.Fp2Ele = (x_[1][0][1], fp1.mul(x_[1][0][0], _2))
        y: Fp.Fp2Ele = (y_[2][0][1], fp1.mul(y_[2][0][0], _2))

        return x, y

    def e(self, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """R-ate, P in G1, Q in G2"""

        fpk = self.fpk
        ec2 = self.ec2
        phi = self._phi
        phii = self._phi_inv
        g_fn = self._g_fn

        _P = (fpk.extend(P[0]), fpk.extend(P[1]))  # P on E(Fp12)
        _Q = phi(Q)  # Q on E(Fp12)

        T = Q
        f1 = fpk.one()
        f2 = fpk.one()
        for i in f"{self._a:b}"[1:]:
            _T = phi(T)  # T on E(Fp12)
            g1, g2 = g_fn(_T, _T, _P)
            f1 = fpk.mul(fpk.mul(f1, f1), g1)
            f2 = fpk.mul(fpk.mul(f2, f2), g2)
            T = ec2.add(T, T)

            if i == "1":
                g1, g2 = g_fn(phi(T), _Q, _P)
                f1 = fpk.mul(f1, g1)
                f2 = fpk.mul(f2, g2)
                T = ec2.add(T, Q)

        Q1 = phii((fpk.pow(_Q[0], self.p), fpk.pow(_Q[1], self.p)))
        Q2 = phii((fpk.pow(_Q[0], self._p2), fpk.pow(_Q[1], self._p2)))
        Q2 = self.ec2.neg(Q2)

        g1, g2 = g_fn(phi(T), phi(Q1), _P)
        f1 = fpk.mul(f1, g1)
        f2 = fpk.mul(f2, g2)

        T = ec2.add(T, Q1)

        g1, g2 = g_fn(phi(T), phi(Q2), _P)
        f1 = fpk.mul(f1, g1)
        f2 = fpk.mul(f2, g2)

        f = fpk.mul(f1, fpk.inv(f2))

        f = fpk.pow(f, self._fexp)
        return f
