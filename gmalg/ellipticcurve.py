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

        self.ec1 = EllipticCurve(self.fp1, 0, b)
        self.ec2 = EllipticCurve(self.fp2, self.fp2.zero(), self.fp2.mul(beta, self.fp2.extend(b)))

        self.G1 = G1
        self.G2 = G2

        self._a = 6 * t + 2
        self._invU = self.fp1.inv(-2)

        self._pm1 = self.p - 1
        self._pa1 = self.p + 1
        self._p2 = self.p * self.p
        self._p2a1 = self._p2 + 1

    def _g_fn(self, U: EcPoint, V: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """g(U, V)(Q). U, V, Q are Fp12 points."""

        fpk = self.fpk

        if U == EllipticCurve.INF or V == EllipticCurve.INF or Q == EllipticCurve.INF:
            return fpk.one()

        xU, yU = U
        xV, yV = V
        xQ, yQ = Q

        if xU == xV:
            if fpk.isoppo(yU, yV):
                return fpk.sub(xQ, xV)
            elif yU == yV:
                _t1 = fpk.smul(3, fpk.mul(xV, xV))  # a = 0
                _t2 = fpk.inv(fpk.smul(2, yV))
                lam = fpk.mul(_t1, _t2)
            else:
                raise errors.UnknownError(f"y1 and y2 is neither equal nor opposite.")
        else:
            lam = fpk.mul(fpk.sub(yU, yV), fpk.inv(fpk.sub(xU, xV)))

        g = fpk.sub(fpk.mul(lam, fpk.sub(xQ, xV)), fpk.sub(yQ, yV))
        return g

    def _phi(self, P: EcPoint) -> EcPoint:
        """Get x, y in E (Fp12) from E' (Fp2), only implemented for beta=(1, 0)"""

        invU = self._invU

        x_, y_ = P

        x: Fp.Fp12Ele = (((0, 0), (0, 0)), ((x_[1] * invU, x_[0]), (0, 0)), ((0, 0), (0, 0)))
        y: Fp.Fp12Ele = (((0, 0), (0, 0)), ((0, 0), (0, 0)), ((y_[1] * invU, y_[0]), (0, 0)))

        return x, y

    def _psi(self, P: EcPoint) -> EcPoint:
        """Get x, y in E' (Fp12) from E (Fp), only implemented for beta=(1, 0)"""

        x_, y_ = P

        x: Fp.Fp12Ele = (((0, 0), (0, x_)), ((0, 0), (0, 0)), ((0, 0), (0, 0)))
        y: Fp.Fp12Ele = (((0, 0), (0, 0)), ((0, 0), (0, 0)), ((0, y_), (0, 0)))

        return x, y

    def _finalexp(self, f: Fp.Fp12Ele) -> Fp.Fp12Ele:
        """f^((p^12 - 1) / n)"""

        print(f"===FVALUE:")
        print(self.fpk.etob(f).hex("\n", 32).upper())
        print(f)
        return self.fpk.pow(f, (self.p ** 12 - 1) // self.n)

        # e = self.fpk.pow
        # m = self.fpk.mul
        # i = self.fpk.inv

        # p = self.p
        # t = self.t

        # f = e(f, self._pm1)
        # f = e(f, self._pa1)
        # f = m(e(e(f, self._p2), self._p2a1), f)
        # f = e(f, self._p2a1)

        # f_t = e(f, t)
        # f_t2 = e(f_t, t)
        # f_t3 = e(f_t2, t)

        # f_p = e(f, p)
        # f_p2 = e(f_p, p)
        # f_p3 = e(f_p2, p)

        # f_t_p = e(f_t, p)
        # f_t2_p = e(f_t2, p)
        # f_t3_p = e(f_t3, p)
        # f_t2_p2 = e(f_t2_p, p)

        # f0 = m(f_p, m(f_p2, f_p3))      # +
        # f1 = e(f, 2)                    # -
        # f2 = e(f_t2_p2, 6)              # +
        # f3 = e(f_t_p, 12)               # -
        # f4 = e(m(f_t2_p, f_t), 18)      # -
        # f5 = e(f_t2, 30)                # -
        # f6 = e(m(f_t3_p, f_t3), 36)     # -

        # part1 = m(f0, f2)
        # part2 = m(f1, m(f3, m(f4, m(f5, f6))))

        # f = m(part1, i(part2))

        # return f

    def __e(self, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """R-ate, P in G1, Q in G2"""

        fpk = self.fpk
        ec2 = self.ec2
        phi = self._phi
        g_fn = self._g_fn

        _P = (fpk.extend(P[0]), fpk.extend(P[1]))  # P on E(Fp12)
        _Q = phi(Q)  # Q on E(Fp12)

        T = Q
        f = fpk.one()
        for i in f"{self._a:b}"[1:]:
            _T = phi(T)  # T on E(Fp12)
            f = fpk.mul(fpk.mul(f, f), g_fn(_T, _T, _P))
            T = ec2.add(T, T)
            f = fpk.mul(f, fpk.inv(fpk.sub(_P[0], phi(T)[0])))

            if i == "1":
                f = fpk.mul(f, g_fn(phi(T), _Q, _P))
                T = ec2.add(T, Q)
                # f = fpk.mul(f, fpk.inv(fpk.sub(_P[0], phi(T)[0])))

        p = self.p
        p_sqr = p * p
        Q1 = (self.fp2.pow(Q[0], p), self.fp2.pow(Q[1], p))
        Q2 = (self.fp2.pow(Q[0], p_sqr), self.fp2.pow(Q[1], p_sqr))

        f = fpk.mul(f, g_fn(phi(T), phi(Q1), _P))

        T = ec2.add(T, Q1)
        f = fpk.mul(f, g_fn(phi(T), phi(ec2.neg(Q2)), _P))

        f = self._finalexp(f)

        return f

    def e(self, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """R-ate, P in G1, Q in G2"""

        fpk = self.fpk
        ec2 = self.ec2
        g_fn = self._g_fn

        _P = self._psi(P)  # P on E'(Fp12)
        _Q = (fpk.extend(Q[0]), fpk.extend(Q[1]))  # Q on E'(Fp12)

        T = Q
        f = fpk.one()
        for i in f"{self._a:b}"[1:]:
            _T = (fpk.extend(T[0]), fpk.extend(T[1]))  # T on E'(Fp12)
            f = fpk.mul(fpk.mul(f, f), g_fn(_T, _T, _P))
            T = ec2.add(T, T)
            # _T = (fpk.extend(T[0]), fpk.extend(T[1]))
            # f = fpk.mul(f, fpk.inv(fpk.sub(_P[0], _T[0])))

            if i == "1":
                _T = (fpk.extend(T[0]), fpk.extend(T[1]))
                f = fpk.mul(f, g_fn(_T, _Q, _P))
                T = ec2.add(T, Q)
                # _T = (fpk.extend(T[0]), fpk.extend(T[1]))
                # f = fpk.mul(f, fpk.inv(fpk.sub(_P[0], _T[0])))

        p = self.p
        p_sqr = p * p
        Q1 = (self.fp2.pow(Q[0], p), self.fp2.pow(Q[1], p))
        Q2 = (self.fp2.pow(Q[0], p_sqr), self.fp2.pow(Q[1], p_sqr))

        _T = (fpk.extend(T[0]), fpk.extend(T[1]))
        _Q1 = (fpk.extend(Q1[0]), fpk.extend(Q1[1]))
        f = fpk.mul(f, g_fn(_T, _Q1, _P))

        T = ec2.add(T, Q1)
        _T = (fpk.extend(T[0]), fpk.extend(T[1]))
        Q2 = ec2.neg(Q2)
        _Q2 = (fpk.extend(Q2[0]), fpk.extend(Q2[1]))
        f = fpk.mul(f, g_fn(_T, _Q2, _P))

        f = self._finalexp(f)

        return f
