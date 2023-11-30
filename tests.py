import unittest

import gmalg
import gmalg.ecfp


class TestSM2(unittest.TestCase):
    def test_sign1(self):
        ecdlp = gmalg.ecfp.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )
        ecc = gmalg.ecfp.EllipticCurveCipher(
            ecdlp, gmalg.SM3,
            lambda _: 0x6CB28D99_385C175C_94F94E93_4817663F_C176D925_DD72B727_260DBAAE_1FB2F96F
        )
        d = 0x128B2FA8_BD433C6C_068C8D80_3DFF7979_2A519A55_171B1B65_0C23661D_15897263
        id_ = b"ALICE123@YAHOO.COM"
        xP = 0x0AE4C779_8AA0F119_471BEE11_825BE462_02BB79E2_A5844495_E97C04FF_4DF2548A
        yP = 0x7C0240F8_8F1CD4E1_6352A73C_17B7F16F_07353E53_A176D684_A9FE0C6B_B798E857

        r, s = ecc.sign(b"message digest", d, id_, xP, yP)
        self.assertEqual(r, 0x40F1EC59_F793D9F4_9E09DCEF_49130D41_94F79FB1_EED2CAA5_5BACDB49_C4E755D1)
        self.assertEqual(s, 0x6FC6DAC3_2C5D5CF1_0C77DFB2_0F7C2EB6_67A45787_2FB09EC5_6327A67E_C7DEEBE7)

        self.assertEqual(ecc.verify(b"message digest", r, s, id_, xP, yP), True)

    def test_sign2(self):
        sm2 = gmalg.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            b"1234567812345678",
            bytes.fromhex("04"
                          "09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                          "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
            rnd_fn=lambda _: 0x59276E27_D506861A_16680F3A_D9C02DCC_EF3CC1FA_3CDBE4CE_6D54B80D_EAC1BC21
        )

        r, s = sm2.sign(b"message digest")
        self.assertEqual(r, bytes.fromhex("F5A03B06 48D2C463 0EEAC513 E1BB81A1 5944DA38 27D5B741 43AC7EAC EEE720B3"))
        self.assertEqual(s, bytes.fromhex("B1B6AA29 DF212FD8 763182BC 0D421CA1 BB9038FD 1F7F42D4 840B69C4 85BBC1AA"))

        self.assertEqual(sm2.verify(b"message digest", r, s), True)

    def test_sign3(self):
        d, pk = gmalg.SM2().generate_keypair()
        sm2 = gmalg.SM2(d, b"test", pk)

        plain = b"random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test random SM2 sign test"
        r, s = sm2.sign(plain)
        self.assertEqual(sm2.verify(plain, r, s), True)

    def test_encrypt1(self):
        ecdlp = gmalg.ecfp.ECDLP(
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_6F4C318C_EFE4AFE3_B6B8551F,
            0xBB8E5E8F_BC115E13_9FE6A814_FE48AAA6_F0ADA1AA_5DF91985,
            0x1854BEBD_C31B21B7_AEFC80AB_0ECD10D5_B1B3308E_6DBF11C1,
            0x4AD5F704_8DE709AD_51236DE6_5E4D4B48_2C836DC6_E4106640,
            0x02BB3A02_D4AAADAC_AE24817A_4CA3A1B0_14B52704_32DB27D2,
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_0FC96219_5DFAE76F_56564677,
        )
        ecc = gmalg.ecfp.EllipticCurveCipher(
            ecdlp, gmalg.SM3,
            lambda _: 0x384F3035_3073AEEC_E7A16543_30A96204_D37982A3_E15B2CB5
        )
        d = 0x58892B80_7074F53F_BF67288A_1DFAA1AC_313455FE_60355AFD
        xP = 0x79F0A954_7AC6D100_531508B3_0D30A565_36BCFC81_49F4AF4A
        yP = 0xAE38F2D8_890838DF_9C19935A_65A8BCC8_994BC792_4672F912

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard", xP, yP)
        self.assertEqual(x1, 0x23FC680B_124294DF_DF34DBE7_6E0C38D8_83DE4D41_FA0D4CF5)
        self.assertEqual(y1, 0x70CF14F2_0DAF0C4D_777F738D_16B16824_D31EEFB9_DE31EE1F)
        self.assertEqual(c2, bytes.fromhex("610567 DBD4854F 51F4F00A DCC01CFE 90B1FB1C"))
        self.assertEqual(c3, bytes.fromhex("6AFB3BCE BD76F82B 252CE5EB 25B57996 86902B8C F2FD8753 6E55EF76 03B09E7C"))

        self.assertEqual(ecc.decrypt(x1, y1, c2, c3, d), b"encryption standard")

    def test_encrypt2(self):
        ecdlp = gmalg.ecfp.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )
        ecc = gmalg.ecfp.EllipticCurveCipher(
            ecdlp, gmalg.SM3,
            lambda _: 0x4C62EEFD_6ECFC2B9_5B92FD6C_3D957514_8AFA1742_5546D490_18E5388D_49DD7B4F
        )
        d = 0x1649AB77_A00637BD_5E2EFE28_3FBF3535_34AA7F7C_B89463F2_08DDBC29_20BB0DA0
        xP = 0x435B39CC_A8F3B508_C1488AFC_67BE491A_0F7BA07E_581A0E48_49A5CF70_628A7E0A
        yP = 0x75DDBA78_F15FEECB_4C7895E2_C1CDF5FE_01DEBB2C_DBADF453_99CCF77B_BA076A42

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard", xP, yP)
        self.assertEqual(x1, 0x245C26FB_68B1DDDD_B12C4B6B_F9F2B6D5_FE60A383_B0D18D1C_4144ABF1_7F6252E7)
        self.assertEqual(y1, 0x76CB9264_C2A7E88E_52B19903_FDC47378_F605E368_11F5C074_23A24B84_400F01B8)
        self.assertEqual(c2, bytes.fromhex("650053 A89B41C4 18B0C3AA D00D886C 00286467"))
        self.assertEqual(c3, bytes.fromhex("9C3D7360 C30156FA B7C80A02 76712DA9 D8094A63 4B766D3A 285E0748 0653426D"))

        self.assertEqual(ecc.decrypt(x1, y1, c2, c3, d), b"encryption standard")

    def test_encrypt3(self):
        sm2 = gmalg.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            P=bytes.fromhex("04"
                            "09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                            "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
            rnd_fn=lambda _: 0x59276E27_D506861A_16680F3A_D9C02DCC_EF3CC1FA_3CDBE4CE_6D54B80D_EAC1BC21,
        )

        cipher = sm2.encrypt(b"encryption standard")
        self.assertEqual(cipher, bytes.fromhex("04"
                                               "04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73"
                                               "E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0"
                                               "59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766"
                                               "21886C A989CA9C 7D580873 07CA9309 2D651EFA"))

        self.assertEqual(sm2.decrypt(cipher), b"encryption standard")

    def test_encrypt4(self):
        d, pk = gmalg.SM2().generate_keypair()
        plain = b"random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test random SM2 encrypt test"

        sm2 = gmalg.SM2(d, P=pk)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

        sm2 = gmalg.SM2(d, P=pk, pc_mode=gmalg.sm2.PC_MODE.COMPRESS)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

        sm2 = gmalg.SM2(d, P=pk, pc_mode=gmalg.sm2.PC_MODE.MIXED)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

    def test_pc(self):
        # 8u7
        sm2 = gmalg.SM2()

        p_b = bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                            "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13")
        p_p = sm2.bytes_to_point(p_b)
        p_pp = sm2.bytes_to_point(sm2.point_to_bytes(*p_p, gmalg.sm2.PC_MODE.COMPRESS))

        self.assertEqual(p_p, p_pp)

        _, p_b = sm2.generate_keypair()
        p_p = sm2.bytes_to_point(p_b)
        p_pp = sm2.bytes_to_point(sm2.point_to_bytes(*p_p, gmalg.sm2.PC_MODE.COMPRESS))

        self.assertEqual(p_p, p_pp)

    def test_y_sqrt(self):
        # 8u3
        ecdlp = gmalg.ecfp.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )

        x = 0x0AE4C779_8AA0F119_471BEE11_825BE462_02BB79E2_A5844495_E97C04FF_4DF2548A
        y = 0x7C0240F8_8F1CD4E1_6352A73C_17B7F16F_07353E53_A176D684_A9FE0C6B_B798E857

        y_ = ecdlp.get_y(x)
        self.assertTrue(y_ == y or ecdlp.p - y_ == y)

        # 8u7
        ecdlp = gmalg.ecfp.ECDLP(
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_6F4C318C_EFE4AFE3_B6B8551F,
            0xBB8E5E8F_BC115E13_9FE6A814_FE48AAA6_F0ADA1AA_5DF91985,
            0x1854BEBD_C31B21B7_AEFC80AB_0ECD10D5_B1B3308E_6DBF11C1,
            0x4AD5F704_8DE709AD_51236DE6_5E4D4B48_2C836DC6_E4106640,
            0x02BB3A02_D4AAADAC_AE24817A_4CA3A1B0_14B52704_32DB27D2,
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_0FC96219_5DFAE76F_56564677,
        )
        x = 0x79F0A954_7AC6D100_531508B3_0D30A565_36BCFC81_49F4AF4A
        y = 0xAE38F2D8_890838DF_9C19935A_65A8BCC8_994BC792_4672F912

        y_ = ecdlp.get_y(x)
        self.assertTrue(y_ == y or ecdlp.p - y_ == y)

    def test_keyxchg1(self):
        ecdlp = gmalg.ecfp.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
            0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2,
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )

        ecc1 = gmalg.ecfp.EllipticCurveCipher(
            ecdlp, gmalg.SM3,
            lambda _: 0x83A2C9C8_B96E5AF7_0BD480B4_72409A9A_327257F1_EBB73F5B_073354B2_48668563
        )
        d1 = 0x6FCBA2EF_9AE0AB90_2BC3BDE3_FF915D44_BA4CC78F_88E2F8E7_F8996D3B_8CCEEDEE
        xP1 = 0x3099093B_F3C137D8_FCBBCDF4_A2AE50F3_B0F216C3_122D7942_5FE03A45_DBFE1655
        yP1 = 0x3DF79E8D_AC1CF0EC_BAA2F2B4_9D51A4B3_87F2EFAF_48233908_6A27A8E0_5BAED98B
        id1 = b"ALICE123@YAHOO.COM"

        ecc2 = gmalg.ecfp.EllipticCurveCipher(
            ecdlp, gmalg.SM3,
            lambda _: 0x33FE2194_0342161C_55619C4A_0C060293_D543C80A_F19748CE_176D8347_7DE71C80
        )
        d2 = 0x5E35D7D3_F3C54DBA_C72E6181_9E730B01_9A84208C_A3A35E4C_2E353DFC_CB2A3B53
        xP2 = 0x245493D4_46C38D8C_C0F11837_4690E7DF_633A8A4B_FB3329B5_ECE604B2_B4F37F43
        yP2 = 0x53C0869F_4B9E1777_3DE68FEC_45E14904_E0DEA45B_F6CECF99_18C85EA0_47C60A4C
        id2 = b"BILL456@YAHOO.COM"

        (x1, y1), t1 = ecc1.begin_key_exchange(d1)
        (x2, y2), t2 = ecc2.begin_key_exchange(d2)

        xv, yv = ecc2.get_secret_point(t2, x1, y1, xP1, yP1)
        xu, yu = ecc1.get_secret_point(t1, x2, y2, xP2, yP2)

        self.assertEqual((xv, yv), (xu, yu))

        K2 = ecc2.generate_skey(16, xv, yv, id1, xP1, yP1, id2, xP2, yP2)
        K1 = ecc1.generate_skey(16, xu, yu, id1, xP1, yP1, id2, xP2, yP2)

        self.assertEqual(K2, K1)

        self.assertEqual(K1, bytes.fromhex("55B0AC62 A6B927BA 23703832 C853DED4"))

    def test_keyxchg2(self):
        PA = bytes.fromhex("04"
                           "160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232"
                           "4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F")
        sm2A = gmalg.SM2(
            bytes.fromhex("81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029"),
            b"1234567812345678", PA,
            rnd_fn=lambda _: 0xD4DE1547_4DB74D06_491C440D_305E0124_00990F3E_390C7E87_153C12DB_2EA60BB3
        )

        PB = bytes.fromhex("04"
                           "6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB"
                           "EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D")
        sm2B = gmalg.SM2(
            bytes.fromhex("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5"),
            b"1234567812345678", PB,
            rnd_fn=lambda _: 0x7E071248_14B30948_9125EAED_10111316_4EBF0F34_58C5BD88_335C1F9D_596243D6
        )

        RA, tA = sm2A.begin_key_exchange()
        RB, tB = sm2B.begin_key_exchange()

        KB = sm2B.end_key_exchange(16, tB, RA, b"1234567812345678", PA, gmalg.sm2.KEYXCHG_MODE.RESPONDER)

        KA = sm2A.end_key_exchange(16, tA, RB, b"1234567812345678", PB, gmalg.sm2.KEYXCHG_MODE.INITIATOR)

        self.assertEqual(KA, KB)
        self.assertEqual(KA, bytes.fromhex("6C893473 54DE2484 C60B4AB1 FDE4C6E5"))

    def test_keyxchg3(self):
        _sm2 = gmalg.SM2()
        dA, PA = _sm2.generate_keypair()
        dB, PB = _sm2.generate_keypair()
        sm2A = gmalg.SM2(dA, b"abcdefghijklmnop", PA)
        sm2B = gmalg.SM2(dB, b"1234567812345678", PB)

        RA, tA = sm2A.begin_key_exchange()
        RB, tB = sm2B.begin_key_exchange()

        KB = sm2B.end_key_exchange(16, tB, RA, b"abcdefghijklmnop", PA, gmalg.sm2.KEYXCHG_MODE.RESPONDER)
        KA = sm2A.end_key_exchange(16, tA, RB, b"1234567812345678", PB, gmalg.sm2.KEYXCHG_MODE.INITIATOR)

        self.assertEqual(KA, KB)


class TestSM3(unittest.TestCase):
    def setUp(self) -> None:
        self.h = gmalg.SM3()

    def test_case1(self):
        self.h.update(b"abc")
        self.assertEqual(self.h.value(), bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))

    def test_case2(self):
        self.h.update(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
        self.assertEqual(self.h.value(), bytes.fromhex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"))

    def test_update(self):
        self.h.update(b"abc")
        self.assertEqual(self.h.value(), bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))
        self.h.update(b"dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcda")
        self.assertEqual(self.h.value(), bytes.fromhex("0d24d8847bb36d29b998d0e191a65e4c39a311303e7b8332fe7fec8341169ad7"))


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
        self.assertRaises(gmalg.errors.IncorrectLengthError, self.c.encrypt, b"123456781234567")
        self.assertRaises(gmalg.errors.IncorrectLengthError, self.c.encrypt, b"12345678123456781")
        self.assertRaises(gmalg.errors.IncorrectLengthError, self.c.decrypt, b"123456781234567")
        self.assertRaises(gmalg.errors.IncorrectLengthError, self.c.decrypt, b"12345678123456781")


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
