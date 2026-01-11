import random
import secrets
import unittest

import gmalg
import gmalg.bcmode as bcmode
import gmalg.ellipticcurve as Ec
import gmalg.primefield as Fp


class TestEllipticCurve(unittest.TestCase):
    def test_ec(self):
        p = 0xB6400000_02A3A6F1_D603AB4F_F58EC745_21F2934B_1A7AEEDB_E56F9B27_E351457D

        ec = Ec.EllipticCurve(Fp.PrimeField(p), 0, 5)
        ec2 = Ec.EllipticCurve(Fp.PrimeField2(p), (0, 0), (5, 0))

        n = 0xB6400000_02A3A6F1_D603AB4F_F58EC744_49F2934B_18EA8BEE_E56EE19C_D69ECF25

        P1 = (0x93DE051D_62BF718F_F5ED0704_487D01D6_E1E40869_09DC3280_E8C4E481_7C66DDDD,
              0x21FE8DDA_4F21E607_63106512_5C395BBC_1C1C00CB_FA602435_0C464CD7_0A3EA616)

        P2 = ((0x85AEF3D0_78640C98_597B6027_B441A01F_F1DD2C19_0F5E93C4_54806C11_D8806141,
              0x37227552_92130B08_D2AAB97F_D34EC120_EE265948_D19C17AB_F9B7213B_AF82D65B),
              (0x17509B09_2E845C12_66BA0D26_2CBEE6ED_0736A96F_A347C8BD_856DC76B_84EBEB96,
              0xA7CF28D5_19BE3DA6_5F317015_3D278FF2_47EFBA98_A71A0811_6215BBA5_C999A7C7))

        self.assertTrue(ec.isvalid(P1), "Not on curve")

        self.assertTrue(ec.mul(n, P1) == ec.INF, "Invalid G")

        self.assertTrue(ec2.isvalid(P2), "Not on curve")

        self.assertTrue(ec2.mul(n, P2) == ec2.INF)


class TestSM2(unittest.TestCase):
    def test_sign1(self):
        ecdlp = Ec.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            (0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
             0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2),
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )
        ecc = gmalg.sm2.SM2Core(
            ecdlp, gmalg.SM3(),
            lambda _: 0x6CB28D99_385C175C_94F94E93_4817663F_C176D925_DD72B727_260DBAAE_1FB2F96F
        )
        d = 0x128B2FA8_BD433C6C_068C8D80_3DFF7979_2A519A55_171B1B65_0C23661D_15897263
        uid = b"ALICE123@YAHOO.COM"
        P = (0x0AE4C779_8AA0F119_471BEE11_825BE462_02BB79E2_A5844495_E97C04FF_4DF2548A,
             0x7C0240F8_8F1CD4E1_6352A73C_17B7F16F_07353E53_A176D684_A9FE0C6B_B798E857)

        r, s = ecc.sign(b"message digest", d, uid, P)
        self.assertEqual(r, 0x40F1EC59_F793D9F4_9E09DCEF_49130D41_94F79FB1_EED2CAA5_5BACDB49_C4E755D1)
        self.assertEqual(s, 0x6FC6DAC3_2C5D5CF1_0C77DFB2_0F7C2EB6_67A45787_2FB09EC5_6327A67E_C7DEEBE7)

        self.assertEqual(ecc.verify(b"message digest", r, s, uid, P), True)

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
        ecdlp = Ec.ECDLP(
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_6F4C318C_EFE4AFE3_B6B8551F,
            0xBB8E5E8F_BC115E13_9FE6A814_FE48AAA6_F0ADA1AA_5DF91985,
            0x1854BEBD_C31B21B7_AEFC80AB_0ECD10D5_B1B3308E_6DBF11C1,
            (0x4AD5F704_8DE709AD_51236DE6_5E4D4B48_2C836DC6_E4106640,
             0x02BB3A02_D4AAADAC_AE24817A_4CA3A1B0_14B52704_32DB27D2),
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_0FC96219_5DFAE76F_56564677,
        )
        ecc = gmalg.sm2.SM2Core(
            ecdlp, gmalg.SM3(),
            lambda _: 0x384F3035_3073AEEC_E7A16543_30A96204_D37982A3_E15B2CB5
        )
        d = 0x58892B80_7074F53F_BF67288A_1DFAA1AC_313455FE_60355AFD
        P = (0x79F0A954_7AC6D100_531508B3_0D30A565_36BCFC81_49F4AF4A,
             0xAE38F2D8_890838DF_9C19935A_65A8BCC8_994BC792_4672F912)

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard", P)
        self.assertEqual(x1, 0x23FC680B_124294DF_DF34DBE7_6E0C38D8_83DE4D41_FA0D4CF5)
        self.assertEqual(y1, 0x70CF14F2_0DAF0C4D_777F738D_16B16824_D31EEFB9_DE31EE1F)
        self.assertEqual(c2, bytes.fromhex("610567 DBD4854F 51F4F00A DCC01CFE 90B1FB1C"))
        self.assertEqual(c3, bytes.fromhex("6AFB3BCE BD76F82B 252CE5EB 25B57996 86902B8C F2FD8753 6E55EF76 03B09E7C"))

        self.assertEqual(ecc.decrypt((x1, y1), c2, c3, d), b"encryption standard")

    def test_encrypt2(self):
        ecdlp = Ec.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            (0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
             0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2),
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )
        ecc = gmalg.sm2.SM2Core(
            ecdlp, gmalg.SM3(),
            lambda _: 0x4C62EEFD_6ECFC2B9_5B92FD6C_3D957514_8AFA1742_5546D490_18E5388D_49DD7B4F
        )
        d = 0x1649AB77_A00637BD_5E2EFE28_3FBF3535_34AA7F7C_B89463F2_08DDBC29_20BB0DA0
        P = (0x435B39CC_A8F3B508_C1488AFC_67BE491A_0F7BA07E_581A0E48_49A5CF70_628A7E0A,
             0x75DDBA78_F15FEECB_4C7895E2_C1CDF5FE_01DEBB2C_DBADF453_99CCF77B_BA076A42)

        (x1, y1), c2, c3 = ecc.encrypt(b"encryption standard", P)
        self.assertEqual(x1, 0x245C26FB_68B1DDDD_B12C4B6B_F9F2B6D5_FE60A383_B0D18D1C_4144ABF1_7F6252E7)
        self.assertEqual(y1, 0x76CB9264_C2A7E88E_52B19903_FDC47378_F605E368_11F5C074_23A24B84_400F01B8)
        self.assertEqual(c2, bytes.fromhex("650053 A89B41C4 18B0C3AA D00D886C 00286467"))
        self.assertEqual(c3, bytes.fromhex("9C3D7360 C30156FA B7C80A02 76712DA9 D8094A63 4B766D3A 285E0748 0653426D"))

        self.assertEqual(ecc.decrypt((x1, y1), c2, c3, d), b"encryption standard")

    def test_encrypt3(self):
        sm2 = gmalg.SM2(
            bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
            pk=bytes.fromhex("04"
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

        sm2 = gmalg.SM2(d, pk=pk)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

        sm2 = gmalg.SM2(d, pk=pk, pc_mode=gmalg.sm2.PC_MODE.COMPRESS)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

        sm2 = gmalg.SM2(d, pk=pk, pc_mode=gmalg.sm2.PC_MODE.MIXED)
        cipher = sm2.encrypt(plain)
        self.assertEqual(sm2.decrypt(cipher), plain)

    def test_pc(self):
        # 8u7
        sm2 = gmalg.sm2
        sm2_ctx = gmalg.SM2()

        p_b = bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                            "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13")
        p_p = sm2.bytes_to_point(p_b)
        p_pp = sm2.bytes_to_point(sm2.point_to_bytes(p_p, gmalg.PC_MODE.COMPRESS))

        self.assertEqual(p_p, p_pp)

        _, p_b = sm2_ctx.generate_keypair()
        p_p = sm2.bytes_to_point(p_b)
        p_pp = sm2.bytes_to_point(sm2.point_to_bytes(p_p, gmalg.PC_MODE.COMPRESS))

        self.assertEqual(p_p, p_pp)

    def test_y_sqrt(self):
        # 8u3
        ecdlp = Ec.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            (0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
             0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2),
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )

        x = 0x0AE4C779_8AA0F119_471BEE11_825BE462_02BB79E2_A5844495_E97C04FF_4DF2548A
        y = 0x7C0240F8_8F1CD4E1_6352A73C_17B7F16F_07353E53_A176D684_A9FE0C6B_B798E857

        y_ = ecdlp.ec.get_y(x)
        self.assertTrue(y_ == y or ecdlp.fp.neg(y_) == y)

        # 8u7
        ecdlp = Ec.ECDLP(
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_6F4C318C_EFE4AFE3_B6B8551F,
            0xBB8E5E8F_BC115E13_9FE6A814_FE48AAA6_F0ADA1AA_5DF91985,
            0x1854BEBD_C31B21B7_AEFC80AB_0ECD10D5_B1B3308E_6DBF11C1,
            (0x4AD5F704_8DE709AD_51236DE6_5E4D4B48_2C836DC6_E4106640,
             0x02BB3A02_D4AAADAC_AE24817A_4CA3A1B0_14B52704_32DB27D2),
            0xBDB6F4FE_3E8B1D9E_0DA8C0D4_0FC96219_5DFAE76F_56564677,
        )
        x = 0x79F0A954_7AC6D100_531508B3_0D30A565_36BCFC81_49F4AF4A
        y = 0xAE38F2D8_890838DF_9C19935A_65A8BCC8_994BC792_4672F912

        y_ = ecdlp.ec.get_y(x)
        self.assertTrue(y_ == y or ecdlp.fp.neg(y_) == y)

    def test_keyxchg1(self):
        ecdlp = Ec.ECDLP(
            0x8542D69E_4C044F18_E8B92435_BF6FF7DE_45728391_5C45517D_722EDB8B_08F1DFC3,
            0x787968B4_FA32C3FD_2417842E_73BBFEFF_2F3C848B_6831D7E0_EC65228B_3937E498,
            0x63E4C6D3_B23B0C84_9CF84241_484BFE48_F61D59A5_B16BA06E_6E12D1DA_27C5249A,
            (0x421DEBD6_1B62EAB6_746434EB_C3CC315E_32220B3B_ADD50BDC_4C4E6C14_7FEDD43D,
             0x0680512B_CBB42C07_D47349D2_153B70C4_E5D7FDFC_BFA36EA1_A85841B9_E46E09A2),
            0x8542D69E_4C044F18_E8B92435_BF6FF7DD_29772063_0485628D_5AE74EE7_C32E79B7,
        )

        ecc1 = gmalg.sm2.SM2Core(
            ecdlp, gmalg.SM3(),
            lambda _: 0x83A2C9C8_B96E5AF7_0BD480B4_72409A9A_327257F1_EBB73F5B_073354B2_48668563
        )
        d1 = 0x6FCBA2EF_9AE0AB90_2BC3BDE3_FF915D44_BA4CC78F_88E2F8E7_F8996D3B_8CCEEDEE
        P1 = (0x3099093B_F3C137D8_FCBBCDF4_A2AE50F3_B0F216C3_122D7942_5FE03A45_DBFE1655,
              0x3DF79E8D_AC1CF0EC_BAA2F2B4_9D51A4B3_87F2EFAF_48233908_6A27A8E0_5BAED98B)
        id1 = b"ALICE123@YAHOO.COM"

        ecc2 = gmalg.sm2.SM2Core(
            ecdlp, gmalg.SM3(),
            lambda _: 0x33FE2194_0342161C_55619C4A_0C060293_D543C80A_F19748CE_176D8347_7DE71C80
        )
        d2 = 0x5E35D7D3_F3C54DBA_C72E6181_9E730B01_9A84208C_A3A35E4C_2E353DFC_CB2A3B53
        P2 = (0x245493D4_46C38D8C_C0F11837_4690E7DF_633A8A4B_FB3329B5_ECE604B2_B4F37F43,
              0x53C0869F_4B9E1777_3DE68FEC_45E14904_E0DEA45B_F6CECF99_18C85EA0_47C60A4C)
        id2 = b"BILL456@YAHOO.COM"

        R1, t1 = ecc1.begin_key_exchange(d1)
        R2, t2 = ecc2.begin_key_exchange(d2)

        V = ecc2.get_secret_point(t2, R1, P1)
        U = ecc1.get_secret_point(t1, R2, P2)

        self.assertEqual(V, U)

        K2 = ecc2.generate_skey(16, V, id1, P1, id2, P2)
        K1 = ecc1.generate_skey(16, U, id1, P1, id2, P2)

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

        KB = sm2B.end_key_exchange(16, tB, RA, b"1234567812345678", PA, gmalg.KEYXCHG_MODE.RESPONDER)
        KA = sm2A.end_key_exchange(16, tA, RB, b"1234567812345678", PB, gmalg.KEYXCHG_MODE.INITIATOR)

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
        self.h.update(b"12345")
        self.assertEqual(self.h.value(), bytes.fromhex("91A7ADDE5B0919D53FFB7DC7253F9F345C3C902A759FE5A2493C70ABB7E25095"))

    def test_case2(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567")
        self.assertEqual(self.h.value(), bytes.fromhex("84FA82E235020F62BEBD48C0995E2AD7CB4B12AC70E90282110D8D972863DC8E"))

    def test_case3(self):
        self.h.update(b"12345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("84A1C27DDCC45E60FF8EF4C55084FD280ECF6CE5A1626B0107A768452F1CFCB3"))

    def test_case4(self):
        self.h.update(b"123456781234567812345678123456781234567812345678123456781")
        self.assertEqual(self.h.value(), bytes.fromhex("9AC2E4FF798A09A5F48FFDCA727EBECB230EC069A185F4D81B84E44738ADAEC1"))

    def test_case5(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("7883E626D07F179E5A5E06445462BD08F08156A8DDCE5FE9E6DAE4D6DAD49CF8"))

    def test_case6(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678"
                      b"1234567812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("16ABFDD57F52837457D36F7E3B5E806E568E3BDA6AD920259FEC4CEB5B382921"))

    def test_update1(self):
        self.h.update(b"123456781")
        self.h.update(b"2345678123456781234567812345678123456781234567")
        self.assertEqual(self.h.value(), bytes.fromhex("84FA82E235020F62BEBD48C0995E2AD7CB4B12AC70E90282110D8D972863DC8E"))

    def test_update2(self):
        self.h.update(b"12345")
        self.h.update(b"678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("84A1C27DDCC45E60FF8EF4C55084FD280ECF6CE5A1626B0107A768452F1CFCB3"))

    def test_update3(self):
        self.h.update(b"12345")
        self.h.update(b"6781234567812345678123456781234567812345678123456781")
        self.assertEqual(self.h.value(), bytes.fromhex("9AC2E4FF798A09A5F48FFDCA727EBECB230EC069A185F4D81B84E44738ADAEC1"))

    def test_update4(self):
        self.h.update(b"12345")
        self.h.update(b"67812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("7883E626D07F179E5A5E06445462BD08F08156A8DDCE5FE9E6DAE4D6DAD49CF8"))

    def test_update51(self):
        self.h.update(b"12345")
        self.h.update(b"6781234567812345678123456781234567812345678123456781234567812345")
        self.assertEqual(self.h.value(), bytes.fromhex("40EDF000B67036C78BC4B394FB3F3201D466E5084FFAA1C4EA6A8427D12F4C40"))

    def test_update52(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.h.update(b"12345")
        self.assertEqual(self.h.value(), bytes.fromhex("40EDF000B67036C78BC4B394FB3F3201D466E5084FFAA1C4EA6A8427D12F4C40"))

    def test_update6(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("16ABFDD57F52837457D36F7E3B5E806E568E3BDA6AD920259FEC4CEB5B382921"))

    def test_update71(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678"
                      b"1234567812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("45418F14DC9077297E5E8480664A294DB2C05F73382469933917E662208B948B"))

    def test_update72(self):
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678"
                      b"1234567812345678123456781234567812345678123456781234567812345678")
        self.h.update(b"1234567812345678123456781234567812345678123456781234567812345678")
        self.assertEqual(self.h.value(), bytes.fromhex("45418F14DC9077297E5E8480664A294DB2C05F73382469933917E662208B948B"))


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


class TestSM4BlockCipherMode(unittest.TestCase):
    def test_ecb(self):
        c = bcmode.BlockCipherModeECB(gmalg.SM4(b"0123456789ABCDEF"))
        plain = secrets.token_bytes(16 * 3)
        cipher = c.encrypt(plain)
        c.reset()
        self.assertEqual(plain, c.decrypt(cipher))

    def test_cbc(self):
        c = bcmode.BlockCipherModeCBC(gmalg.SM4(b"0123456789ABCDEF"), b"0123456789ABCDEF")
        plain = secrets.token_bytes(16 * 3)
        cipher = c.encrypt(plain)
        c.reset()
        self.assertEqual(plain, c.decrypt(cipher))

    def test_cfb(self):
        for seg_len in range(1, 17):
            for _ in range(10):
                c = bcmode.BlockCipherModeCFB(gmalg.SM4(b"0123456789ABCDEF"), b"0123456789ABCDEF", seg_len)
                seg = b"123"
                lengths = [random.randint(1, 10) for _ in range(100)]

                seq1 = lengths.copy()
                random.shuffle(seq1)
                seq2 = seq1.copy()
                random.shuffle(seq2)

                cipher = b"".join(c.encrypt(seg * i) for i in seq1)

                seq2_idx = [0]
                for i in seq2:
                    seq2_idx.append(seq2_idx[-1] + i)
                c.reset()
                plain = b"".join(c.decrypt(cipher[seq2_idx[i] * len(seg):seq2_idx[i + 1] * len(seg)]) for i in range(len(seq2)))
                self.assertEqual(plain, seg * sum(lengths))

    def test_ofb(self):
        for _ in range(10):
            c = bcmode.BlockCipherModeOFB(gmalg.SM4(b"0123456789ABCDEF"), b"0123456789ABCDEF")
            seg = b"123"
            lengths = [random.randint(1, 10) for _ in range(100)]

            seq1 = lengths.copy()
            random.shuffle(seq1)
            seq2 = seq1.copy()
            random.shuffle(seq2)

            cipher = b"".join(c.encrypt(seg * i) for i in seq1)

            seq2_idx = [0]
            for i in seq2:
                seq2_idx.append(seq2_idx[-1] + i)
            c.reset()
            plain = b"".join(c.decrypt(cipher[seq2_idx[i] * len(seg):seq2_idx[i + 1] * len(seg)]) for i in range(len(seq2)))
            self.assertEqual(plain, seg * sum(lengths))


class TestSM9(unittest.TestCase):
    def test_sign(self):
        hid_s = b"\x01"
        msk_s = bytes.fromhex("0130E7 8459D785 45CB54C5 87E02CF4 80CE0B66 340F319F 348A1D5B 1F2DC5F4")
        mpk_s = bytes.fromhex("04"
                              "9F64080B 3084F733 E48AFF4B 41B56501 1CE0711C 5E392CFB 0AB1B679 1B94C408"
                              "29DBA116 152D1F78 6CE843ED 24A3B573 414D2177 386A92DD 8F14D656 96EA5E32"
                              "69850938 ABEA0112 B57329F4 47E3A0CB AD3E2FDB 1A77F335 E89E1408 D0EF1C25"
                              "41E00A53 DDA532DA 1A7CE027 B7A46F74 1006E85F 5CDFF073 0E75C05F B4E3216D")
        kgc = gmalg.SM9KGC(hid_s=hid_s, msk_s=msk_s, mpk_s=mpk_s)

        uid = b"Alice"
        sk_s = kgc.generate_sk_sign(uid)

        self.assertEqual(sk_s, bytes.fromhex("04"
                                             "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
                                             "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"))

        sm9 = gmalg.SM9(
            hid_s=hid_s, mpk_s=mpk_s, sk_s=sk_s, uid=uid,
            rnd_fn=lambda _: 0x033C86_16B06704_813203DF_D0096502_2ED15975_C662337A_ED648835_DC4B1CBE
        )

        message = b"Chinese IBS standard"
        h, S = sm9.sign(message)

        self.assertEqual(h, bytes.fromhex("823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB"))
        self.assertEqual(S, bytes.fromhex("04"
                                          "73BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C"
                                          "856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05"))

        self.assertTrue(sm9.verify(message, h, S))

    def test_keyxchg(self):
        hid_e = b"\x02"
        msk_e = bytes.fromhex("02E65B 0762D042 F51F0D23 542B13ED 8CFA2E9A 0E720636 1E013A28 3905E31F")
        mpk_e = bytes.fromhex("04"
                              "91745426 68E8F14A B273C094 5C3690C6 6E5DD096 78B86F73 4C435056 7ED06283"
                              "54E598C6 BF749A3D ACC9FFFE DD9DB686 6C50457C FC7AA2A4 AD65C316 8FF74210")
        kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

        uid_A = b"Alice"
        sk_e_A = kgc.generate_sk_encrypt(uid_A)
        self.assertEqual(sk_e_A, bytes.fromhex("04"
                                               "0FE8EAB3 95199B56 BF1D75BD 2CD610B6 424F08D1 092922C5 882B52DC D6CA832A"
                                               "7DA57BC5 0241F9E5 BFDDC075 DD9D32C7 777100D7 36916CFC 165D8D36 E0634CD7"
                                               "83A457DA F52CAD46 4C903B26 062CAF93 7BB40E37 DADED9ED A401050E 49C8AD0C"
                                               "6970876B 9AAD1B7A 50BB4863 A11E574A F1FE3C59 75161D73 DE4C3AF6 21FB1EFB"))

        uid_B = b"Bob"
        sk_e_B = kgc.generate_sk_encrypt(uid_B)
        self.assertEqual(sk_e_B, bytes.fromhex("04"
                                               "74CCC3AC 9C383C60 AF083972 B96D05C7 5F12C890 7D128A17 ADAFBAB8 C5A4ACF7"
                                               "01092FF4 DE893626 70C21711 B6DBE52D CD5F8E40 C6654B3D ECE573C2 AB3D29B2"
                                               "44B0294A A04290E1 524FF3E3 DA8CFD43 2BB64DE3 A8040B5B 88D1B5FC 86A4EBC1"
                                               "8CFC48FB 4FF37F1E 27727464 F3C34E21 53861AD0 8E972D16 25FC1A7B D18D5539"))

        sm9_A = gmalg.SM9(
            hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e_A, uid=uid_A,
            rnd_fn=lambda _: 0x5879_DD1D51E1_75946F23_B1B41E93_BA31C584_AE59A426_EC1046A4_D03B06C8
        )

        sm9_B = gmalg.SM9(
            hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e_B, uid=uid_B,
            rnd_fn=lambda _: 0x018B98_C44BEF9F_8537FB7D_071B2C92_8B3BC65B_D3D69E1E_EE213564_905634FE
        )

        rA, RA = sm9_A.begin_key_exchange(uid_B)
        rB, RB = sm9_B.begin_key_exchange(uid_A)

        KB = sm9_B.end_key_exchange(16, rB, RB, uid_A, RA, gmalg.KEYXCHG_MODE.RESPONDER)
        KA = sm9_A.end_key_exchange(16, rA, RA, uid_B, RB, gmalg.KEYXCHG_MODE.INITIATOR)

        self.assertEqual(KA.hex(), KB.hex())
        self.assertEqual(KA, bytes.fromhex("C5C13A8F 59A97CDE AE64F16A 2272A9E7"))

    def test_encapsulate(self):
        hid_e = b"\x03"
        msk_e = bytes.fromhex("01EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
        mpk_e = bytes.fromhex("04"
                              "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
                              "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1")
        kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

        uid = b"Bob"

        sk_e = kgc.generate_sk_encrypt(uid)
        self.assertEqual(sk_e, bytes.fromhex("04"
                                             "94736ACD 2C8C8796 CC4785E9 38301A13 9A059D35 37B64141 40B2D31E ECF41683"
                                             "115BAE85 F5D8BC6C 3DBD9E53 42979ACC CF3C2F4F 28420B1C B4F8C0B5 9A19B158"
                                             "7AA5E475 70DA7600 CD760A0C F7BEAF71 C447F384 4753FE74 FA7BA92C A7D3B55F"
                                             "27538A62 E7F7BFB5 1DCE0870 4796D94C 9D56734F 119EA447 32B50E31 CDEB75C1"))

        sm9 = gmalg.SM9(
            hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e, uid=uid,
            rnd_fn=lambda _: 0x7401_5F8489C0_1EF42704_56F9E647_5BFB602B_DE7F33FD_482AB4E3_684A6722
        )

        K, C = sm9.encapsulate(32, uid)  # encapsulate key to self

        self.assertEqual(K, bytes.fromhex("4FF5CF86 D2AD40C8 F4BAC98D 76ABDBDE 0C0E2F0A 829D3F91 1EF5B2BC E0695480"))
        self.assertEqual(C, bytes.fromhex("04"
                                          "1EDEE2C3 F4659144 91DE44CE FB2CB434 AB02C308 D9DC5E20 67B4FED5 AAAC8A0F"
                                          "1C9B4C43 5ECA35AB 83BB7341 74C0F78F DE81A533 74AFF3B3 602BBC5E 37BE9A4C"))

        self.assertEqual(sm9.decapsulate(C, 32), K)

    def test_encrypt(self):
        hid_e = b"\x03"
        msk_e = bytes.fromhex("01EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
        mpk_e = bytes.fromhex("04"
                              "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
                              "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1")
        kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

        uid = b"Bob"

        sk_e = kgc.generate_sk_encrypt(uid)
        self.assertEqual(sk_e, bytes.fromhex("04"
                                             "94736ACD 2C8C8796 CC4785E9 38301A13 9A059D35 37B64141 40B2D31E ECF41683"
                                             "115BAE85 F5D8BC6C 3DBD9E53 42979ACC CF3C2F4F 28420B1C B4F8C0B5 9A19B158"
                                             "7AA5E475 70DA7600 CD760A0C F7BEAF71 C447F384 4753FE74 FA7BA92C A7D3B55F"
                                             "27538A62 E7F7BFB5 1DCE0870 4796D94C 9D56734F 119EA447 32B50E31 CDEB75C1"))

        sm9 = gmalg.SM9(
            hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e, uid=uid,
            rnd_fn=lambda _: 0xAAC0_541779C8_FC45E3E2_CB25C12B_5D2576B2_129AE8BB_5EE2CBE5_EC9E785C
        )

        plain = b"Chinese IBE standard"
        cipher = sm9.encrypt(plain, uid)  # encrypt data to self

        self.assertEqual(cipher, bytes.fromhex("04"
                                               "24454711 64490618 E1EE2052 8FF1D545 B0F14C8B CAA44544 F03DAB5D AC07D8FF"
                                               "42FFCA97 D57CDDC0 5EA405F2 E586FEB3 A6930715 532B8000 759F1305 9ED59AC0"
                                               "BA672387 BCD6DE50 16A158A5 2BB2E7FC 429197BC AB70B25A FEE37A2B 9DB9F367"
                                               "1B5F5B0E 95148968 2F3E64E1 378CDD5D A9513B1C"))

        self.assertEqual(sm9.decrypt(cipher), plain)

    def test_pc(self):
        sm9 = gmalg.sm9
        kgc = gmalg.SM9KGC()

        _, p_bytes = kgc.generate_keypair_encrypt()
        p_point = sm9.bytes_to_point_1(p_bytes)
        p_point_2 = sm9.bytes_to_point_1(sm9.point_to_bytes_1(p_point, gmalg.PC_MODE.COMPRESS))

        self.assertEqual(p_point, p_point_2)

        p_bytes = bytes.fromhex("04"
                                "9F64080B 3084F733 E48AFF4B 41B56501 1CE0711C 5E392CFB 0AB1B679 1B94C408"
                                "29DBA116 152D1F78 6CE843ED 24A3B573 414D2177 386A92DD 8F14D656 96EA5E32"
                                "69850938 ABEA0112 B57329F4 47E3A0CB AD3E2FDB 1A77F335 E89E1408 D0EF1C25"
                                "41E00A53 DDA532DA 1A7CE027 B7A46F74 1006E85F 5CDFF073 0E75C05F B4E3216D")
        p_point = sm9.bytes_to_point_2(p_bytes)
        p_point_2 = sm9.bytes_to_point_2(sm9.point_to_bytes_2(p_point, gmalg.PC_MODE.COMPRESS))

        self.assertEqual(p_point, p_point_2)

        _, p_bytes = kgc.generate_keypair_sign()
        p_point = sm9.bytes_to_point_2(p_bytes)
        p_point_2 = sm9.bytes_to_point_2(sm9.point_to_bytes_2(p_point, gmalg.PC_MODE.COMPRESS))

        self.assertEqual(p_point, p_point_2)


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
