# gmalg

GM algorithms implemented in pure python.

## Install

```bat
pip install gmalg
```

## Implemented Core Algorithms

- [x] ZUC Stream Cipher Algorithm
- [x] SM2 Public Key Cryptograhpic Algorithm Based on Elliptic Curves
- [x] SM3 Cryptogrpahic Hash Algorithm
- [x] SM4 Block Cipher Algorithm
- [ ] SM9 Identification Cryptographic Algorithm

## Usage

```python
import gmalg

# ZUC stream cipher
zuc = gmalg.ZUC(bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"),
                bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"))

print(zuc.generate().hex())
print(zuc.generate().hex())

# SM3 hash
sm3 = gmalg.SM3()
print(sm3.value().hex())

sm3.update(b"I'm SM3 algorithm.")
print(sm3.value().hex())

# SM4 block cipher
sm4 = gmalg.SM4(bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"))
cipher = sm4.encrypt(b"0102030405060708")
print(cipher.hex())
print(sm4.decrypt(cipher))

# SM2 sign/verify usage
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

# SM2 encrypt/decrypt usage
sm2 = gmalg.SM2(
    bytes.fromhex("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8"),
    P=bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                    "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
)

cipher = sm2.encrypt(b"I'm SM2 encrypt/decrypt algorithm.")
print(cipher.hex())
print(sm2.decrypt(cipher))
```

Go to [gmalg-docs:TODO] see more detailed usages.

---

*If you think this project is helpful to you, :star: it and let more people see!*
