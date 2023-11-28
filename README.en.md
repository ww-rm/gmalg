# gmalg

GM algorithms implemented in pure python.

## Install

```bat
pip install gmalg
```

## Implemented Core Algorithms

- [x] ZUC Stream Cipher Algorithm
- [x] SM2 Public Key Cryptograhpic Algorithm Based on Elliptic Curves
  - Sign/Verify
  - Key exchange
  - Encrypt/Decrypt
- [x] SM3 Cryptogrpahic Hash Algorithm
- [x] SM4 Block Cipher Algorithm
- [ ] SM9 Identification Cryptographic Algorithm

## Usage

### ZUC Generate pseudo-random key stream

```python
import gmalg

zuc = gmalg.ZUC(bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"),
                bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"))

print(zuc.generate().hex())
print(zuc.generate().hex())
```

### SM3 Compute hash value

```python
import gmalg

sm3 = gmalg.SM3()
print(sm3.value().hex())

sm3.update(b"I'm SM3 algorithm.")
print(sm3.value().hex())
```

### SM4 Encrypt/Decrypt

```python
import gmalg

sm4 = gmalg.SM4(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))
cipher = sm4.encrypt(b"0102030405060708")
print(cipher.hex())
print(sm4.decrypt(cipher))
```

### SM2 Sign/Verify

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

### SM2 Encrypt/Decrypt

```python
import gmalg

sm2 = gmalg.SM2(
    bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
    P=bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                    "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
)

cipher = sm2.encrypt(b"I'm SM2 encrypt/decrypt algorithm.")
print(cipher.hex())
print(sm2.decrypt(cipher))
```

### SM2 Key exchange

```python
import gmalg

PA = bytes.fromhex("04 160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232"
                   "4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F")
sm2A = gmalg.SM2(
    bytes.fromhex("81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029"),
    b"1234567812345678", PA
)

PB = bytes.fromhex("04 6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB"
                   "EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D")
sm2B = gmalg.SM2(
    bytes.fromhex("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5"),
    b"1234567812345678", PB
)

RA, tA = sm2A.begin_key_exchange()
RB, tB = sm2B.begin_key_exchange()

KB = sm2B.end_key_exchange(16, tB, RA, b"1234567812345678", PA, gmalg.sm2.KEYXCHG_MODE.RESPONDER)
KA = sm2A.end_key_exchange(16, tA, RB, b"1234567812345678", PB, gmalg.sm2.KEYXCHG_MODE.INITIATOR)

print(KA == KB)
print(KA.hex())
```

Go to [docs:TODO] see more detailed usages.

---

*If you think this project is helpful to you, :star: it and let more people see!*
