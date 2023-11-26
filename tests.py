import unittest

import gmalg
import gmalg.core


class TestSM2(unittest.TestCase):
    def _rnd_sign1(self, k: int) -> int:
        return 0x6CB28D99_385C175C_94F94E93_4817663F_C176D925_DD72B727_260DBAAE_1FB2F96F

    def test_sign1(self):
        ecdlp = gmalg.core.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2
        )
        ecc = gmalg.core.EllipticCurveCipher(
            ecdlp, gmalg.SM3, self._rnd_sign1,
            d=bytes.fromhex("128B2FA8 BD433C6C 068C8D80 3DFF7979 2A519A55 171B1B65 0C23661D 15897263"),
            xP=bytes.fromhex("0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A"),
            yP=bytes.fromhex("7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857"),
            id_=b"ALICE123@YAHOO.COM"
        )

        r, s = ecc.sign(b"message digest")
        self.assertEqual(r, bytes.fromhex("40F1EC59 F793D9F4 9E09DCEF 49130D41 94F79FB1 EED2CAA5 5BACDB49 C4E755D1"))
        self.assertEqual(s, bytes.fromhex("6FC6DAC3 2C5D5CF1 0C77DFB2 0F7C2EB6 67A45787 2FB09EC5 6327A67E C7DEEBE7"))

        self.assertEqual(ecc.verify(b"message digest", r, s), True)

    def _rnd_sign2(self, k: int) -> int:
        return 0x59276E27_D506861A_16680F3A_D9C02DCC_EF3CC1FA_3CDBE4CE_6D54B80D_EAC1BC21

    def test_sign2(self):
        sm2 = gmalg.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            bytes.fromhex("09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"),
            bytes.fromhex("CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
            b"1234567812345678",
            rnd_fn=self._rnd_sign2
        )

        r, s = sm2.sign(b"message digest")
        self.assertEqual(r, bytes.fromhex("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"))
        self.assertEqual(s, bytes.fromhex("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"))

        self.assertEqual(sm2.verify(b"message digest", r, s), True)

    def test_sign3(self):
        d, pk = gmalg.SM2().generate_keypair()
        sm2 = gmalg.SM2(d, *pk, b"test")

        plain = b"random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test"
        r, s = sm2.sign(plain)
        self.assertEqual(sm2.verify(plain, r, s), True)

    def _rnd_encrypt1(self, k: int) -> int:
        return 0x384F3035_3073AEEC_E7A16543_30A96204_D37982A3_E15B2CB5

    def test_encrypt1(self):
        ecdlp = gmalg.core.ECDLP(
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_6F4C318C_EFE4AFE3_B6B8551F,
            0xBB8E5E8F_BC115E13_9FE6A814_FE48AAA6_F0ADA1AA_5DF91985,
            0x1854BEBD_C31B21B7_AEFC80AB_0ECD10D5_B1B3308E_6DBF11C1,
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_0FC96219_5DFAE76F_56564677,
            0x4AD5F704_8DE709AD_51236DE6_5E4D4B48_2C836DC6_E4106640,
            0x02BB3A02_D4AAADAC_AE24817A_4CA3A1B0_14B52704_32DB27D2
        )
        ecc = gmalg.core.EllipticCurveCipher(
            ecdlp, gmalg.SM3, self._rnd_encrypt1,
            d=bytes.fromhex("58892B80 7074F53F BF67288A 1DFAA1AC 313455FE 60355AFD"),
            xP=bytes.fromhex("79F0A954 7AC6D100 531508B3 0D30A565 36BCFC81 49F4AF4A"),
            yP=bytes.fromhex("AE38F2D8 890838DF 9C19935A 65A8BCC8 994BC792 4672F912"),
        )

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard")
        self.assertEqual(x1, bytes.fromhex("23FC680B 124294DF DF34DBE7 6E0C38D8 83DE4D41 FA0D4CF5"))
        self.assertEqual(y1, bytes.fromhex("70CF14F2 0DAF0C4D 777F738D 16B16824 D31EEFB9 DE31EE1F"))
        self.assertEqual(c2, bytes.fromhex("610567 DBD4854F 51F4F00A DCC01CFE 90B1FB1C"))
        self.assertEqual(c3, bytes.fromhex("6AFB3BCE BD76F82B 252CE5EB 25B57996 86902B8C F2FD8753 6E55EF76 03B09E7C"))

        self.assertEqual(ecc.decrypt(x1, y1, c2, c3), b"encryption standard")

    def _rnd_encrypt2(self, k: int) -> int:
        return 0x4C62EEFD_6ECFC2B9_5B92FD6C_3D957514_8AFA1742_5546D490_18E5388D_49DD7B4F

    def test_encrypt2(self):
        ecdlp = gmalg.core.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2
        )
        ecc = gmalg.core.EllipticCurveCipher(
            ecdlp, gmalg.SM3, self._rnd_encrypt2,
            d=bytes.fromhex("1649AB77 A00637BD 5E2EFE28 3FBF3535 34AA7F7C B89463F2 08DDBC29 20BB0DA0"),
            xP=bytes.fromhex("435B39CC A8F3B508 C1488AFC 67BE491A 0F7BA07E 581A0E48 49A5CF70 628A7E0A"),
            yP=bytes.fromhex("75DDBA78 F15FEECB 4C7895E2 C1CDF5FE 01DEBB2C DBADF453 99CCF77B BA076A42"),
        )

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard")
        self.assertEqual(x1, bytes.fromhex("245C26FB 68B1DDDD B12C4B6B F9F2B6D5 FE60A383 B0D18D1C 4144ABF1 7F6252E7"))
        self.assertEqual(y1, bytes.fromhex("76CB9264 C2A7E88E 52B19903 FDC47378 F605E368 11F5C074 23A24B84 400F01B8"))
        self.assertEqual(c2, bytes.fromhex("650053 A89B41C4 18B0C3AA D00D886C 00286467"))
        self.assertEqual(c3, bytes.fromhex("9C3D7360 C30156FA B7C80A02 76712DA9 D8094A63 4B766D3A 285E0748 0653426D"))

        self.assertEqual(ecc.decrypt(x1, y1, c2, c3), b"encryption standard")

    def _rnd_encrypt3(self, k: int) -> int:
        return 0x59276E27_D506861A_16680F3A_D9C02DCC_EF3CC1FA_3CDBE4CE_6D54B80D_EAC1BC21

    def test_encrypt3(self):
        sm2 = gmalg.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            bytes.fromhex("09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"),
            bytes.fromhex("CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
            rnd_fn=self._rnd_encrypt3,
        )

        (x1, y1), c2, c3 = sm2.encrypt(b"encryption standard")
        self.assertEqual(x1, bytes.fromhex("04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73"))
        self.assertEqual(y1, bytes.fromhex("E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0"))
        self.assertEqual(c2, bytes.fromhex("21886C A989CA9C 7D580873 07CA9309 2D651EFA"))
        self.assertEqual(c3, bytes.fromhex("59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766"))

        self.assertEqual(sm2.decrypt(x1, y1, c2, c3), b"encryption standard")

    def test_encrypt4(self):
        d, pk = gmalg.SM2().generate_keypair()
        sm2 = gmalg.SM2(d, *pk)

        plain = b"random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test"
        (x1, y1), c2, c3 = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(x1, y1, c2, c3), plain)


class TestSM3(unittest.TestCase):
    def setUp(self) -> None:
        self.h = gmalg.SM3()

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
        self.c = gmalg.SM4(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))

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
        z = gmalg.ZUC(bytes.fromhex("00000000000000000000000000000000"), bytes.fromhex("00000000000000000000000000000000"))
        self.assertEqual(z.generate(), bytes.fromhex("27bede74"))
        self.assertEqual(z.generate(), bytes.fromhex("018082da"))

    def test_case2(self):
        z = gmalg.ZUC(bytes.fromhex("ffffffffffffffffffffffffffffffff"), bytes.fromhex("ffffffffffffffffffffffffffffffff"))
        self.assertEqual(z.generate(), bytes.fromhex("0657cfa0"))
        self.assertEqual(z.generate(), bytes.fromhex("7096398b"))

    def test_case3(self):
        z = gmalg.ZUC(bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"), bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"))
        self.assertEqual(z.generate(), bytes.fromhex("14f1c272"))
        self.assertEqual(z.generate(), bytes.fromhex("3279c419"))


if __name__ == "__main__":
    unittest.main()
