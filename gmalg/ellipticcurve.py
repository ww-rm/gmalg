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

    def __g_fn(self, U: EcPoint, V: EcPoint, Q: EcPoint) -> Fp.FpExEle:
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

        g1 = ...
        g2 = fpk.smul(1, yV)
        print("g2 0")
        print(fpk.etob(yV).hex("\n", 32))
        exit(0)

        g = fpk.sub(fpk.mul(lam, fpk.sub(xQ, xV)), fpk.sub(yQ, yV))
        return g

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

    def __e2(self, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """R-ate, P in G1, Q in G2"""

        fpk = self.fpk
        ec2 = self.ec2
        g_fn = self._g_fn

        print("Q")
        print(self.fp2.etob(Q[0]).hex("\n", 32))
        print(self.fp2.etob(Q[1]).hex("\n", 32))

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

        print("T")
        print(self.fp2.etob(T[0]).hex("\n", 32))
        print(self.fp2.etob(T[1]).hex("\n", 32))

        p = self.p
        p_sqr = p * p

        # Q1
        # 8F15BC5BB81CE698B09869C432648C97817E3B73BDD7CE3729CF73CE683AB459
        # 97D27388E4FB2C13BAA6E3C1D395DE5921ABC0CFC435F9695600846CB42B6120
        # 7F3FB8552D495A7CD8FA6002FDB286C336AA3773AAE8A0E946BEDD37EAC2C27A
        # 5F43E2149827B5BE435D595B89BDD6B2EC59AE835178943767A1FA1124D8C635

        # Q2
        # 3E063B991CA5701716E3ED9077039CF1A5867A0618E4E285965E0C0842D31299
        # 6DF6D272CFCE0C9B4DBE9FD4AEF228E5E05E9F588BCB668BC6EBAE161D4102EE
        # 69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25
        # 41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF073E75C05FB4E3216D

        # Q1 = (self.fp2.pow((self.fp1.neg(Q[0][0]), Q[0][1]), p), self.fp2.pow((self.fp1.neg(Q[1][0]), Q[1][1]), p))
        Q1 = (self.fp2.pow(Q[0], p), self.fp2.pow(Q[1], p))
        Q2 = (self.fp2.pow(Q[0], p_sqr), self.fp2.pow(Q[1], p_sqr))
        Q2 = ec2.neg(Q2)

        Q1 = (
            (0x8F15BC5BB81CE698B09869C432648C97817E3B73BDD7CE3729CF73CE683AB459,
             0x97D27388E4FB2C13BAA6E3C1D395DE5921ABC0CFC435F9695600846CB42B6120),
            (0x7F3FB8552D495A7CD8FA6002FDB286C336AA3773AAE8A0E946BEDD37EAC2C27A,
             0x5F43E2149827B5BE435D595B89BDD6B2EC59AE835178943767A1FA1124D8C635)
        )
        Q2 = (
            (0x3E063B991CA5701716E3ED9077039CF1A5867A0618E4E285965E0C0842D31299,
             0x6DF6D272CFCE0C9B4DBE9FD4AEF228E5E05E9F588BCB668BC6EBAE161D4102EE),
            (0x69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25,
             0x41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF073E75C05FB4E3216D)
        )

        print("Q1")
        print(self.fp2.etob(Q1[0]).hex("\n", 32))
        print(self.fp2.etob(Q1[1]).hex("\n", 32))

        print("Q2 neg")
        print(self.fp2.etob(Q2[0]).hex("\n", 32))
        print(self.fp2.etob(Q2[1]).hex("\n", 32))

        # _T = (fpk.extend(T[0]), fpk.extend(T[1]))
        # _Q1 = (fpk.extend(Q1[0]), fpk.extend(Q1[1]))
        _P = (fpk.extend(P[0]), fpk.extend(P[1]))
        _T = self._phi(T)
        _Q1 = self._phi(Q1)
        f = fpk.mul(f, g_fn(_T, _Q1, _P))

        T = ec2.add(T, Q1)

        print("T+Q1")
        print(self.fp2.etob(T[0]).hex("\n", 32))
        print(self.fp2.etob(T[1]).hex("\n", 32))

        # _T = (fpk.extend(T[0]), fpk.extend(T[1]))
        # _Q2 = (fpk.extend(Q2[0]), fpk.extend(Q2[1]))
        _T = self._phi(T)
        _Q2 = self._phi(Q2)

        f = fpk.mul(f, g_fn(_T, _Q2, _P))

        print("FBefore")
        print(fpk.etob(f).hex("\n", 32))

        # f = fpk.btoe(
        #     bytes.fromhex("2B2C8A0C2A46C563A8C005422DAEFC8BC8BFFB24A8BCB8C4201EAC57F1A34D34 \
        #                    1081873EAD980945BC11B1EB91A5F4368B8B742EC6FD040BD6D34F74D44AEC9E \
        #                    B48D062BAA6D0AF2DB237575696C16F4F1EC9A521DA21C6E06BB66B721F60538 \
        #                    426613720865BA113E9A0B11223C46FE51D7C72B299CB4C8DBD06F93E1CBF730 \
        #                    5F86A6C09D9FE24CD5E1AFFD962133C2966BAB2191CC1959AF08E4D56BA5CE45 \
        #                    80FBC475B9A86FE85B8ABBF93BE6F9A4650948679AAD6745AE7B1F8112862615 \
        #                    7F0542C461ED19D44D920A479B623CEAAEAA62363E540018BF6C28192C424E4C \
        #                    26597F29BD0F4355DB4276A3283605B56CAF3D7C668A26D2AE656ACD5348E5A8 \
        #                    8BC3A7EE71ABEE3620357178BA03B963340EEDE6B29D7B68F2314337F4738DB6 \
        #                    0D9074973C488BF9CC27FB44D9D67B3A4CD18CC137A59E4A850DC59727577E4F \
        #                    9553BFBF3DB33ECE3C17368CF24CF633EC37176D60626A8F1226A4B589F34C4C \
        #                    A12263A2D4399C5A7F73680C0F8DAE18BA6D1201F52C86C9CEA880A359845B28")
        # )

        f = fpk.pow(f, (self.p ** 12 - 1) // self.n)
        return f

    def e(self, P: EcPoint, Q: EcPoint) -> Fp.FpExEle:
        """R-ate, P in G1, Q in G2"""

        fpk = self.fpk
        ec2 = self.ec2
        phi = self._phi
        g_fn = self._g_fn
        ext = lambda point: (fpk.extend(point[0]), fpk.extend(point[1]))

        print("Q")
        print(self.fp2.etob(Q[0]).hex("\n", 32))
        print(self.fp2.etob(Q[1]).hex("\n", 32))

        _P = (fpk.extend(P[0]), fpk.extend(P[1]))  # P on E(Fp12)
        _Q = phi(Q)  # Q on E(Fp12)

        T = Q
        f1 = fpk.one()
        f2 = fpk.one()
        for i in f"{self._a:b}"[1:]:
            _T = phi(T)  # T on E(Fp12)
            # _T = ext(T)
            g1, g2 = g_fn(_T, _T, _P)
            print("g1 0")
            print(fpk.etob(g1).hex("\n", 32))
            print("g2 0")
            print(fpk.etob(g2).hex("\n", 32))

            g = fpk.mul(g1, fpk.inv(g2))
            print("g 0")
            print(fpk.etob(g).hex("\n", 32))
            exit(0)
            f1 = fpk.mul(fpk.mul(f1, f1), g1)
            f2 = fpk.mul(f2, g2)
            T = ec2.add(T, T)

            if i == "1":
                g1, g2 = g_fn(phi(T), _Q, _P)
                f1 = fpk.mul(f1, g1)
                f2 = fpk.mul(f2, g2)
                T = ec2.add(T, Q)

        print("T")
        print(self.fp2.etob(T[0]).hex("\n", 32))
        print(self.fp2.etob(T[1]).hex("\n", 32))

        p = self.p
        p_sqr = p * p

        # Q1 = (self.fp2.pow((self.fp1.neg(Q[0][0]), Q[0][1]), p), self.fp2.pow((self.fp1.neg(Q[1][0]), Q[1][1]), p))
        # Q1 = (self.fp2.pow(Q[0], p), self.fp2.pow(Q[1], p))
        # Q2 = (self.fp2.pow(Q[0], p_sqr), self.fp2.pow(Q[1], p_sqr))
        # Q2 = ec2.neg(Q2)

        Q1 = (
            (0x8F15BC5BB81CE698B09869C432648C97817E3B73BDD7CE3729CF73CE683AB459,
             0x97D27388E4FB2C13BAA6E3C1D395DE5921ABC0CFC435F9695600846CB42B6120),
            (0x7F3FB8552D495A7CD8FA6002FDB286C336AA3773AAE8A0E946BEDD37EAC2C27A,
             0x5F43E2149827B5BE435D595B89BDD6B2EC59AE835178943767A1FA1124D8C635)
        )
        Q2 = (
            (0x3E063B991CA5701716E3ED9077039CF1A5867A0618E4E285965E0C0842D31299,
             0x6DF6D272CFCE0C9B4DBE9FD4AEF228E5E05E9F588BCB668BC6EBAE161D4102EE),
            (0x69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25,
             0x41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF073E75C05FB4E3216D)
        )

        print("Q1")
        print(self.fp2.etob(Q1[0]).hex("\n", 32))
        print(self.fp2.etob(Q1[1]).hex("\n", 32))

        print("Q2 neg")
        print(self.fp2.etob(Q2[0]).hex("\n", 32))
        print(self.fp2.etob(Q2[1]).hex("\n", 32))

        # _T = (fpk.extend(T[0]), fpk.extend(T[1]))
        # _Q1 = (fpk.extend(Q1[0]), fpk.extend(Q1[1]))
        g1, g2 = g_fn(phi(T), phi(Q1), _P)
        f1 = fpk.mul(f1, g1)
        f2 = fpk.mul(f2, g2)

        T = ec2.add(T, Q1)

        print("T+Q1")
        print(self.fp2.etob(T[0]).hex("\n", 32))
        print(self.fp2.etob(T[1]).hex("\n", 32))

        g1, g2 = g_fn(phi(T), phi(Q2), _P)

        f1 = fpk.mul(f1, g1)
        f2 = fpk.mul(f2, g2)

        f = fpk.mul(f1, fpk.inv(f2))

        print("FBefore")
        print(fpk.etob(f).hex("\n", 32))

        # f = fpk.btoe(
        #     bytes.fromhex("2B2C8A0C2A46C563A8C005422DAEFC8BC8BFFB24A8BCB8C4201EAC57F1A34D34 \
        #                    1081873EAD980945BC11B1EB91A5F4368B8B742EC6FD040BD6D34F74D44AEC9E \
        #                    B48D062BAA6D0AF2DB237575696C16F4F1EC9A521DA21C6E06BB66B721F60538 \
        #                    426613720865BA113E9A0B11223C46FE51D7C72B299CB4C8DBD06F93E1CBF730 \
        #                    5F86A6C09D9FE24CD5E1AFFD962133C2966BAB2191CC1959AF08E4D56BA5CE45 \
        #                    80FBC475B9A86FE85B8ABBF93BE6F9A4650948679AAD6745AE7B1F8112862615 \
        #                    7F0542C461ED19D44D920A479B623CEAAEAA62363E540018BF6C28192C424E4C \
        #                    26597F29BD0F4355DB4276A3283605B56CAF3D7C668A26D2AE656ACD5348E5A8 \
        #                    8BC3A7EE71ABEE3620357178BA03B963340EEDE6B29D7B68F2314337F4738DB6 \
        #                    0D9074973C488BF9CC27FB44D9D67B3A4CD18CC137A59E4A850DC59727577E4F \
        #                    9553BFBF3DB33ECE3C17368CF24CF633EC37176D60626A8F1226A4B589F34C4C \
        #                    A12263A2D4399C5A7F73680C0F8DAE18BA6D1201F52C86C9CEA880A359845B28")
        # )

        # f = fpk.pow(f, (self.p ** 12 - 1) // self.n)
        return f
