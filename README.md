# gmalg

[![Unittest](https://github.com/ww-rm/gmalg/actions/workflows/python-test.yml/badge.svg)](https://github.com/ww-rm/gmalg/actions/workflows/python-test.yml)
[![PyPI](https://github.com/ww-rm/gmalg/actions/workflows/python-publish.yml/badge.svg)](https://github.com/ww-rm/gmalg/actions/workflows/python-publish.yml)

国密算法的纯 Python 实现, 不依赖除标准库以外的任何第三方库.

- ~~国密体验装~~
- ~~课程作业专供~~

## 安装

```bat
pip install gmalg
```

## 实现的核心算法

- ZUC 序列密码算法
- SM2 椭圆曲线公钥密码算法
  - 签名验签
  - 密钥交换
  - 加密解密
- SM3 密码杂凑算法
- SM4 分组密码算法 (含部分工作模式)
- SM9 标识密码算法
  - 签名验签
  - 密钥交换
  - 密钥封装
  - 加密解密 (基于密钥派生函数的序列密码算法)

## 用法

详细文档: [gmalg.readthedocs.io](https://gmalg.readthedocs.io)

### ZUC 生成伪随机密钥流

```python
import gmalg

zuc = gmalg.ZUC(bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"),
                bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"))

print(zuc.generate().hex())
print(zuc.generate().hex())
```

### SM3 计算哈希值

```python
import gmalg

sm3 = gmalg.SM3()
print(sm3.value().hex())

sm3.update(b"I'm SM3 algorithm.")
print(sm3.value().hex())
```

### SM4 加密/解密

```python
import gmalg

sm4 = gmalg.SM4(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))
cipher = sm4.encrypt(b"0102030405060708")
print(cipher.hex())
print(sm4.decrypt(cipher))
```

### SM4 加密/解密 (工作模式)

```python
import gmalg

data = b"12345678123456781234"
print(data.hex())

key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
iv = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
sm4 = gmalg.SM4Cipher(key, gmalg.BC_MODE.CBC, gmalg.DataPadder(16, gmalg.PADDING_MODE.PKCS7), iv=iv)

cipher = sm4.encrypt(data)
print(cipher.hex())

sm4.reset()  # reset internal states
plain = sm4.decrypt(cipher)
print(plain)
```

### SM2 签名/验签

```python
import gmalg

sm2 = gmalg.SM2(
    bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
    b"1234567812345678",
    bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                  "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
)
msg = b"I'm SM2 sign/verify algorithm."
r, s = sm2.sign(msg)
print(r.hex())
print(s.hex())
print(sm2.verify(msg, r, s))
```

### SM2 加密/解密

```python
import gmalg

sm2 = gmalg.SM2(
    bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
    pk=bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                    "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
)

cipher = sm2.encrypt(b"I'm SM2 encrypt/decrypt algorithm.")
print(cipher.hex())
print(sm2.decrypt(cipher))
```

### SM2 密钥交换

```python
import gmalg

PA = bytes.fromhex("04 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232"
                   "4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F")
sm2A = gmalg.SM2(
    bytes.fromhex("81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029"),
    b"abcdefghijklmnopqrstuvwxyz", PA
)

PB = bytes.fromhex("04 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB"
                   "EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D")
sm2B = gmalg.SM2(
    bytes.fromhex("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5"),
    b"1234567812345678", PB
)

RA, tA = sm2A.begin_key_exchange()
RB, tB = sm2B.begin_key_exchange()

KB = sm2B.end_key_exchange(16, tB, RA, b"abcdefghijklmnopqrstuvwxyz", PA, gmalg.KEYXCHG_MODE.RESPONDER)
KA = sm2A.end_key_exchange(16, tA, RB, b"1234567812345678", PB, gmalg.KEYXCHG_MODE.INITIATOR)

print(KA == KB)
print(KA.hex())
```

### SM9 签名/验签

```python
import gmalg

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

print(sk_s.hex())

sm9 = gmalg.SM9(hid_s=hid_s, mpk_s=mpk_s, sk_s=sk_s, uid=uid)

message = b"Chinese IBS standard"
h, S = sm9.sign(message)

print(h.hex())
print(S.hex())

print(sm9.verify(message, h, S))
```

### SM9 密钥交换

```python
import gmalg

hid_e = b"\x02"
msk_e = bytes.fromhex("02E65B 0762D042 F51F0D23 542B13ED 8CFA2E9A 0E720636 1E013A28 3905E31F")
mpk_e = bytes.fromhex("04"
                      "91745426 68E8F14A B273C094 5C3690C6 6E5DD096 78B86F73 4C435056 7ED06283"
                      "54E598C6 BF749A3D ACC9FFFE DD9DB686 6C50457C FC7AA2A4 AD65C316 8FF74210")
kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

uid_A = b"Alice"
sk_e_A = kgc.generate_sk_encrypt(uid_A)
print(sk_e_A.hex())

uid_B = b"Bob"
sk_e_B = kgc.generate_sk_encrypt(uid_B)
print(sk_e_B.hex())

sm9_A = gmalg.SM9(hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e_A, uid=uid_A)
sm9_B = gmalg.SM9(hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e_B, uid=uid_B)

rA, RA = sm9_A.begin_key_exchange(uid_B)
rB, RB = sm9_B.begin_key_exchange(uid_A)

KB = sm9_B.end_key_exchange(16, rB, RB, uid_A, RA, gmalg.KEYXCHG_MODE.RESPONDER)
KA = sm9_A.end_key_exchange(16, rA, RA, uid_B, RB, gmalg.KEYXCHG_MODE.INITIATOR)

print(KA == KB)
print(KA.hex())
```

### SM9 密钥封装

```python
import gmalg

hid_e = b"\x03"
msk_e = bytes.fromhex("01EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
mpk_e = bytes.fromhex("04"
                      "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
                      "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1")
kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

uid = b"Bob"

sk_e = kgc.generate_sk_encrypt(uid)
print(sk_e.hex())

sm9 = gmalg.SM9(hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e, uid=uid)

K, C = sm9.encapsulate(32, uid)  # encapsulate key to self

print(K.hex())
print(C.hex())

print(sm9.decapsulate(C, 32) == K)
```

### SM9 加密/解密

```python
import gmalg

hid_e = b"\x03"
msk_e = bytes.fromhex("01EDEE 3778F441 F8DEA3D9 FA0ACC4E 07EE36C9 3F9A0861 8AF4AD85 CEDE1C22")
mpk_e = bytes.fromhex("04"
                      "787ED7B8 A51F3AB8 4E0A6600 3F32DA5C 720B17EC A7137D39 ABC66E3C 80A892FF"
                      "769DE617 91E5ADC4 B9FF85A3 1354900B 20287127 9A8C49DC 3F220F64 4C57A7B1")
kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)

uid = b"Bob"

sk_e = kgc.generate_sk_encrypt(uid)
print(sk_e.hex())

sm9 = gmalg.SM9(hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e, uid=uid)

plain = b"Chinese IBE standard"
cipher = sm9.encrypt(plain, uid)  # encrypt data to self

print(cipher.hex())

print(sm9.decrypt(cipher))
```

更多详细用法可以查看[文档](https://gmalg.readthedocs.io).

## 关于密文顺序

无论是 SM2 还是 SM9, 均遵循国标要求按照 `C1|C3|C2` 的顺序构造和解析密文**字节流**.

但是在计算各部分数值的时候, 代码里是没有顺序的, 仅仅按照三个独立的 `C1`, `C2`, `C3` 对象返回, 这与密文字节流的构造是分开的.

## 关于 PC 字节

在 SM2/SM9 算法中, 当椭圆曲线上的点转换成字节串时, 需要在开头附加一个字节 PC 加以标识, 非无穷远点按国标要求有三类表示模式:

- 压缩表示形式, PC = `0x02` 或 `0x03`
- 未压缩表示形式, PC = `0x04`
- 混合表示形式, PC = `0x06` 或 `0x07`

在 `gmalg` 中所有需要将椭圆曲线上的点转换成字节串时, **一定**带有 PC 标识字节, 但是部分其他项目代码在实现时可能只实现了未压缩表示形式 (PC = `0x04`), 并且可能在提供参数时省略了开头的 PC 字节, 因此在使用时需要注意甄别.

可能涉及密文, 公钥, 随机点等参数的字节串表示形式.

---

*If you think this project is helpful to you, :star: it and let more people see!*
