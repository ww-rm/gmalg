import unittest

import gmalg.core


class TestSM2(unittest.TestCase):
    def _const_rnd1(self, k: int) -> int:
        return 0x59276E27_D506861A_16680F3A_D9C02DCC_EF3CC1FA_3CDBE4CE_6D54B80D_EAC1BC21

    def _const_rnd2(self, k: int) -> int:
        return 0x6CB28D99_385C175C_94F94E93_4817663F_C176D925_DD72B727_260DBAAE_1FB2F96F

    def test_sign(self):
        sm2 = gmalg.core.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            bytes.fromhex("09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"),
            bytes.fromhex("CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
            b"1234567812345678",
            rnd_fn=self._const_rnd1
        )

        r, s = sm2.sign(b"message digest")
        self.assertEqual(r, bytes.fromhex("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"))
        self.assertEqual(s, bytes.fromhex("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"))

        self.assertEqual(sm2.verify(b"message digest", r, s), True)

    def test_sign2(self):
        ecc = gmalg.core.SM2(
            bytes.fromhex("128B2FA8 BD433C6C 068C8D80 3DFF7979 2A519A55 171B1B65 0C23661D 15897263"),
            bytes.fromhex("0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A"),
            bytes.fromhex("7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857"),
            b"ALICE123@YAHOO.COM",
            p=bytes.fromhex("8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"),
            a=bytes.fromhex("787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498"),
            b=bytes.fromhex("63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A"),
            n=bytes.fromhex("8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"),
            xG=bytes.fromhex("421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"),
            yG=bytes.fromhex("0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"),
            rnd_fn=self._const_rnd2
        )

        r, s = ecc.sign(b"message digest")
        self.assertEqual(r, bytes.fromhex("40F1EC59 F793D9F4 9E09DCEF 49130D41 94F79FB1 EED2CAA5 5BACDB49 C4E755D1"))
        self.assertEqual(s, bytes.fromhex("6FC6DAC3 2C5D5CF1 0C77DFB2 0F7C2EB6 67A45787 2FB09EC5 6327A67E C7DEEBE7"))

        self.assertEqual(ecc.verify(b"message digest", r, s), True)


class TestSM3(unittest.TestCase):
    def setUp(self) -> None:
        self.h = gmalg.core.SM3()

    def test_case1(self):
        self.h.update(b"abc")
        self.assertEqual(self.h.value, bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))

    def test_case2(self):
        self.h.update(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
        self.assertEqual(self.h.value, bytes.fromhex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"))

    def test_update(self):
        self.h.update(b"abc")
        self.assertEqual(self.h.value, bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))
        self.h.update(b"dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcda")
        self.assertEqual(self.h.value, bytes.fromhex("0d24d8847bb36d29b998d0e191a65e4c39a311303e7b8332fe7fec8341169ad7"))


class TestSM4(unittest.TestCase):
    def setUp(self) -> None:
        self.c = gmalg.core.SM4(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))

    def test_case1(self):
        cipher = self.c.encrypt(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))
        self.assertEqual(cipher, bytes.fromhex("681edf34d206965e86b3e94f536e4246"))

        plain = self.c.decrypt(cipher)
        self.assertEqual(plain, bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))

    @unittest.skip("SM4 1000000 times encrypt and decrypt.")
    def test_case2(self):
        cipher = self.c.encrypt(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))
        for _ in range(999999):
            cipher = self.c.encrypt(cipher)
        self.assertEqual(cipher, bytes.fromhex("595298c7c6fd271f0402f804c33d3f66"))

        plain = self.c.decrypt(cipher)
        for _ in range(999999):
            plain = self.c.decrypt(plain)
        self.assertEqual(plain, bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))

    def test_raises(self):
        self.assertRaises(ValueError, self.c.encrypt, b"123456781234567")
        self.assertRaises(ValueError, self.c.encrypt, b"12345678123456781")
        self.assertRaises(ValueError, self.c.decrypt, b"123456781234567")
        self.assertRaises(ValueError, self.c.decrypt, b"12345678123456781")


class TestZUC(unittest.TestCase):
    def test_case1(self):
        z = gmalg.core.ZUC(bytes.fromhex("00000000000000000000000000000000"), bytes.fromhex("00000000000000000000000000000000"))
        self.assertEqual(z.generate(), bytes.fromhex("27bede74"))
        self.assertEqual(z.generate(), bytes.fromhex("018082da"))

    def test_case2(self):
        z = gmalg.core.ZUC(bytes.fromhex("ffffffffffffffffffffffffffffffff"), bytes.fromhex("ffffffffffffffffffffffffffffffff"))
        self.assertEqual(z.generate(), bytes.fromhex("0657cfa0"))
        self.assertEqual(z.generate(), bytes.fromhex("7096398b"))

    def test_case3(self):
        z = gmalg.core.ZUC(bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"), bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"))
        self.assertEqual(z.generate(), bytes.fromhex("14f1c272"))
        self.assertEqual(z.generate(), bytes.fromhex("3279c419"))


if __name__ == "__main__":
    unittest.main()
