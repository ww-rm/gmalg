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

    def _g_fn(self, U: EcPoint, V: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """g(U, V)(Q)"""

        fp = self._fp

        if U == self.INF or V == self.INF or Q == self.INF:
            return fp.one()

        xU, yU = U
        xV, yV = V
        xQ, yQ = Q

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
        g = fp.add(fp.sub(_t, yQ), yV)
        return g

    def miller(self, c: int, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """Miller function."""

        fp = self._fp
        g = self._g_fn

        xP, yP = P
        xQ, yQ = Q

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


class ECDLP:
    """Elliptic Curve Discrete Logarithm Problem"""

    def __init__(self, p: int, a: int, b: int, G: EcPoint, n: int, h: int = 1) -> None:
        """Elliptic Curve Discrete Logarithm Problem

        Elliptic Curve (Fp): y^2 = x^3 + ax + b (mod p)

        Base point: (xG, yG)
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


# class ECBIDH:
#     def __init__(
#         self, p: int, t: int, k: int, d1: int, d2: int, b: Fp.FpEle, beta: Fp.FpEle,
#         xG1: Fp.FpEle, yG1: Fp.FpEle, xG2: Fp.FpEle, yG2: Fp.FpEle,
#         n: int, cf: int = 1
#     ) -> None:
#         """BN Elliptic Curve Bilinear Inverse Diffie-Hellman."""

#         if k == 12:
#             self.fpk = Fp.PrimeField12(p)
#             self.eck = EllipticCurve12(p, self.fpk.zero(), self.fpk.extend(b))
#         else:
#             raise NotImplementedError(f"k: {k}")

#         if d1 > d2:
#             raise errors.InvalidArgumentError(f"d1 should less or equal than d2, {d1} > {d2}")

#         if d1 == 1:
#             self.ec1 = EllipticCurve(p, 0, b)
#         else:
#             raise NotImplementedError(f"d1: {d1}")

#         if d2 == 2:
#             _fp = Fp.PrimeField2(p)
#             self.ec2 = EllipticCurve2(p, _fp.zero(), _fp.mul(beta, _fp.extend(b)))
#         else:
#             raise NotImplementedError(f"d2: {d2}")

#         self.t = t
#         self.xG1 = xG1
#         self.yG1 = yG1
#         self.xG2 = xG2
#         self.yG2 = yG2
#         self.n = n
#         self.cf = cf

#     def e(self) -> Fp.FpExEle:
#         ...
