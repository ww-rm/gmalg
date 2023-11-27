# gmalg

使用纯 Python 实现的国密算法库~~国密体验装~~.

## 安装

```bat
pip install gmalg
```

## 已实现的核心算法

- [x] 祖冲之序列密码算法
- [x] SM2 椭圆曲线公钥密码算法
- [x] SM3 密码杂凑算法
- [x] SM4 分组密码算法
- [ ] SM9 标识密码算法

## 用法

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
    P=bytes.fromhex("04 09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020"
                    "CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13"),
)

cipher = sm2.encrypt(b"I'm SM2 encrypt/decrypt algorithm.")
print(cipher.hex())
print(sm2.decrypt(cipher))
```

更多详细用法可以查看[文档:TODO]

---

*If you think this project is helpful to you, :star: it and let more people see!*
