# 快速开始

只需简单的几行代码即可开始国密探索之旅!

## SM2 公钥密码算法

### 简介

SM2 是一种基于椭圆曲线上离散对数问题的公钥密码算法, 属于非对称算法.

常见的非对称算法还有 RSA, 使用非对称算法能够完成对数据的签名/验签, 加密/解密等操作.

非对称密码算法的特点是加密/解密以及签名/验签所使用的密钥是不同的, 分为公钥与私钥两部分, 两者成对出现, 由私钥可以获得公钥, 但是由公钥不能获得私钥.

因此使用非对称算法时, 公钥可以公开, 但是私钥需要秘密保存.

在使用非对称密码进行数据加密解密时, 若用户 A 需要将数据加密后传递给用户 B, 则用户 A 使用用户 B 的公钥进行数据加密, 用户 B 收到密文后, 使用自己秘密保管的私钥进行解密得到明文信息.

在使用非对称密码进行数据签名验签时, 若用户 A 需要对数据进行签名后传递给用户 B, 则用户 A 使用自己的私钥对数据进行签名, 用户 B 收到数据与签名后, 使用用户 A 的公钥进行验签, 验证数据与签名是否来自于用户 A.

### 签名/验签

在 gmalg 中使用 SM2 密码算法之前, 若没有密钥, 则首先需要随机生成一对可用的公私钥.

```python
import gmalg

sk, pk = gmalg.SM2().generate_keypair()

print(sk.hex())
print(pk.hex())
```

然后实例化 [`SM2`][gmalg.SM2] 并设置密钥参数.

```python
sm2 = gmalg.SM2(sk, b"Alice", pk)
```

此处还可以额外指定用户 ID, 用于签名/验签操作.

按如下方式使用 SM2 进行签名/验签.

```python
msg = b"I'm SM2 sign/verify algorithm."

r, s = sm2.sign(msg)

print(r.hex())
print(s.hex())

verify_result = sm2.verify(msg, r, s)
print(verify_result)
```

### 加密/解密

类似的, 也可以使用 SM2 进行加密/解密.

```python
plain = b"I'm SM2 encrypt/decrypt algorithm."

cipher = sm2.encrypt(plain)
print(cipher.hex())

plain_restore = sm2.decrypt(cipher)
print(plain_restore)
```

### 密钥交换

SM2 还支持密钥交换, 能够在发起方和响应方之间计算出一个相同的密钥数据.

```python
import gmalg

uid_A = b"Alice"
uid_B = b"Bod"

_sm2 = gmalg.SM2()
sk_A, pk_A = _sm2.generate_keypair()
sk_B, pk_B = _sm2.generate_keypair()

print(sk_A.hex())
print(pk_A.hex())

print(sk_B.hex())
print(pk_B.hex())

user_A = gmalg.SM2(sk_A, uid_A, pk_A)
user_B = gmalg.SM2(sk_B, uid_B, pk_B)

RA, tA = user_A.begin_key_exchange()
RB, tB = user_B.begin_key_exchange()

KB = user_B.end_key_exchange(16, tB, RA, uid_A, pk_A, gmalg.KEYXCHG_MODE.RESPONDER)
KA = user_A.end_key_exchange(16, tA, RB, uid_B, pk_B, gmalg.KEYXCHG_MODE.INITIATOR)

print(KA == KB)
print(KA.hex())
```

使用 [`begin_key_exchange`][gmalg.SM2.begin_key_exchange] 生成密钥交换必需的交换数据.

使用 [`end_key_exchange`][gmalg.SM2.end_key_exchange] 来结束密钥交换并得到指定长度的密钥, 需要指定调用者是发起方还是响应方.

### 参数需求

在使用 SM2 算法的功能时, 并不是每次都提供所有参数, 存在以下参数需求关系:

| 参数   | 签名  | 验签   | 加密 | 解密   | 密钥交换 |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 私钥   | √    |        |      |  √    |  √     |
| ID     | √    | √      |      |       |  √    |
| 公钥   |      | √      |  √   |       |        |

## SM3 密码杂凑算法

SM3 是一种哈希算法, 它可以将有限长度的消息压缩成固定长度的输出内容.

哈希函数具有不可逆的特点, 即由输入可以容易得到输出, 但是由输出得到原始输入是困难的, 类似常见的算法还有 MD5, SHA1, SHA256 等等, 因此哈希函数常常用于生成消息摘要, 作为数据的指纹信息.

---

要在 gmalg 中使用 SM3 算法, 可以按以下方式运行代码.

```python
import gmalg

sm3 = gmalg.SM3()

hash_value = sm3.value()
print(hash_value.hex())

sm3.update(b"I'm SM3 algorithm.")
hash_value = sm3.value()
print(hash_value.hex())
```

使用前需要实例化 [`SM3`][gmalg.SM3] 类, 使用 [`value`][gmalg.SM3.value] 方法可以随时获取当前内容的哈希值, 使用 [`update`][gmalg.SM3.update] 方法可以向内部继续添加内容.

SM3 的哈希值长度为 32 字节. 即使是空值, SM3 算法也有固定的哈希值输出.

## SM4 分组密码算法

### 简介

SM4 是一种分组密码算法, 它可以使用固定长度的密钥对固定长度的明文数据块进行加密, 得到与明文等长的密文数据块.

分组密码属于对称密码算法, 通常需要一个固定长度的密钥来控制算法的运行, 且加密和解密的过程是对称可逆的.

分组密码的一大特点就是只能对指定长度的数据块进行加密和解密, 因此大部分时候都不直接使用分组密码, 而是使用带有工作模式的分组密码.

常见的工作模式有 ECB, CBC, CFB 等, 它们有各自的特点, 能够扩展分组密码的功能, 使其能对任意长度数据进行加密, 在 gmalg 中, 仅仅实现了无工作模式的原始 SM4 算法.

---

按以下方式使用 SM4 算法.

```python
import gmalg

key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
sm4 = gmalg.SM4(key)

cipher = sm4.encrypt(b"0102030405060708")
print(cipher.hex())

plain = sm4.decrypt(cipher)
print(plain)
```

初始化 [`SM4`][gmalg.SM4] 类, 需要指定一次密钥, 密钥长度为 16 字节. 之后使用 [`encrypt`][gmalg.SM4.encrypt] 和 [`decrypt`][gmalg.SM4.decrypt] 方法进行加密和解密, 分组长度为 16 字节.

### 带有工作模式的 SM4 算法

本项目中实现了一些常见的工作模式:

- ECB: 电码本模式 (Electronic Codebook). 该模式要求加解密的数据都必须是分组大小的整数倍.
- CBC: 密文链接模式 (Cipher Block Chaining). 该模式同样要求加解密的数据必须是分组大小的整数倍, 且需要提供一个与分组大小相同的初始向量 IV.
- CFB: 密文反馈模式 (Cipher Feedback). 该模式可以对任意长度的数据进行加解密, 无需填充, 但是需要提供一个与分组大小相同的初始向量 IV, 且需要指定数据的片段移位长度, 该长度为小于等于分组长度的正整数.
- OFB: 输出反馈模式 (Output Feedback). 该模式与 CFB 类似, 可以对任意长度的数据进行加解密, 无需填充, 但是同样需要提供一个与分组大小相同的初始向量 IV.

由上述可知, 部分工作模式需要对数据进行填充, 因此项目内提供了一些常见的填充方法, 具体可见 [`PADDING_MODE`][gmalg.PADDING_MODE], 可以按一下方式对数据进行填充和去填充操作:

```python
import gmalg

data = b"1234567"
print(data.hex())

padder = gmalg.DataPadder(16, gmalg.PADDING_MODE.PKCS7)
padded_data = padder.pad(data)
print(padded_data.hex())

unpadded_data = padder.unpad(padded_data)
print(unpadded_data.hex())
```

可以使用指定工作模式和填充方法的 [`SM4Cipher`][gmalg.SM4Cipher] 对数据进行加解密:

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

[`SM4Cipher`][gmalg.SM4Cipher] 类可用于流式数据加解密, 且提供了 [`reset`][gmalg.SM4Cipher.reset] 方法, 用于重置内部运算状态.

## SM9 标识密码算法

### 简介

SM9 是一套基于标识的非对称密码算法, 类似于 SM2, SM9 也有可以被公开的部分和被用户秘密保存的密钥信息.

但是传统的非对称密码算法的公钥是一串不好记忆的二进制数据, 而 SM9 的出现则解决了这个问题, 将一个人类易于记忆的 ID 作为算法中的公开部分, 用户要使用 SM9 给他人进行信息传递时, 只需要知道对方的用户 ID, 而不需要获取公钥信息, 从而降低了潜在的安全风险.

SM9 与 SM2 等传统非对称密码算法的不同之处还在于, SM9 需要有一个密钥生成中心 (Key Generation Center, KGC), 负责管理系统主密钥与用户私钥的生成.

KGC 的角色类似于传统的证书机构, 是保证算法安全的可信第三方, KGC 可以知晓用户所有的秘密信息, 并且负责用户私钥的产生和更新.

### 密钥管理

SM9 中的密钥管理分成两部分, 一部分是系统主密钥 (Master Key), 另一部分是用户密钥.

系统主密钥为一对公私钥, 分别称为主公钥 (Master Public Key) 和主私钥 (Master Secret Key); 而用户拥有用户 ID 和用户私钥.

其中主公钥被公开, 主私钥由 KGC 秘密保管; 用户 ID 公开, 用户私钥由 KGC 根据用户 ID 使用主私钥产生, 由用户秘密保管.

进一步, 在 SM9 中, 加密/解密和签名/验签所使用的密钥是不同的两套, 有各自的主密钥与用户密钥, 它们的数据类型也不尽相同.

KGC 在生成用户私钥时, 还会额外用到一个生成标识符 (hid), 该标识符也是加密和签名分开各自拥有并随主公钥一起公开的.

### 签名/验签

在有了以上必要的基础知识储备后, 我们便可以开始使用 gmalg 中的 SM9 算法.

使用签名/验签, 如果没有系统主密钥对, 则首先进行随机生成, 并确定 1 个字节的用户密钥生成标识符.

实例化类 [`SM9KGC`][gmalg.SM9KGC] 获取 KGC 的功能, 实例化类 [`SM9`][gmalg.SM9] 获得用户功能.

```python
import gmalg

hid_s = b"\x01"
msk_s, mpk_s = gmalg.SM9KGC().generate_keypair_sign()
print(msk_s.hex())
print(mpk_s.hex())

kgc = gmalg.SM9KGC(hid_s=hid_s, msk_s=msk_s, mpk_s=mpk_s)
```

接着生成用户的签名私钥.

```python
uid = b"Alice"
sk_s = kgc.generate_sk_sign(uid)
print(sk_s.hex())
```

然后进行签名/验签操作.

```python
sm9 = gmalg.SM9(hid_s=hid_s, mpk_s=mpk_s, sk_s=sk_s, uid=uid)

message = b"Chinese IBS standard"
h, S = sm9.sign(message)

print(h.hex())
print(S.hex())

verify_result = sm9.verify(message, h, S)
print(verify_result)
```

### 加密/解密

同样的, 类似于签名/验签操作, 在使用加密/解密功能之前, 也需要确定系统主密钥与用户密钥生成标识符.

```python
import gmalg

hid_e = b"\x03"
msk_e, mpk_e = gmalg.SM9KGC().generate_keypair_encrypt()
print(msk_e.hex())
print(mpk_e.hex())

kgc = gmalg.SM9KGC(hid_e=hid_e, msk_e=msk_e, mpk_e=mpk_e)
```

接着生成用户的加密私钥.

```python
uid = b"Alice"
sk_e = kgc.generate_sk_encrypt(uid)
print(sk_e.hex())
```

然后进行加密/解密操作.

```python
sm9 = gmalg.SM9(hid_e=hid_e, mpk_e=mpk_e, sk_e=sk_e, uid=uid)

plain = b"Chinese IBE standard"

cipher = sm9.encrypt(plain, uid)  # encrypt data to self
print(cipher.hex())

plain_restore = sm9.decrypt(cipher)
print(plain_restore)
```

### 密钥封装

SM9 支持密钥封装与解封操作, 本质上对应加密/解密其中的一部分内容, 因此使用方法与加密/解密类似.

```python
K, C = sm9.encapsulate(32, uid)  # encapsulate key to self
print(K.hex())
print(C.hex())

K_restore = sm9.decapsulate(C, 32)
print(K_restore == K)
```

### 密钥交换

与 SM2 类似, SM9 同样也支持密钥交换操作, 只是将双方得到公钥换成了用户 ID, 同样能够在发起方和响应方之间交换出相同的密钥串.

在密钥交换中, 使用的是系统加密主密钥和用户加密私钥.

```python
import gmalg

hid_e = b"\x02"
msk_e, mpk_e = gmalg.SM9KGC().generate_keypair_encrypt()
print(msk_e.hex())
print(mpk_e.hex())

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

print(KA.hex() == KB.hex())
print(KA.hex())
```

同样的, 在使用 [`end_key_exchange`][gmalg.SM9.end_key_exchange] 时, 也需要指定调用者是发起方还是响应方.

### 参数需求

在用户使用 SM9 算法的功能时, 并不是每次都提供所有参数, 存在以下参数需求关系:

| 参数                | 签名   | 验签  | 加密   | 解密  | 密钥封装 | 密钥解封 | 密钥交换 |
| :---:               | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 签名私钥生成标识符   |      | √       |      |       |       |        |       |
| 签名主公钥          | √    | √       |      |       |        |       |       |
| 加密私钥生成标识符   |      |         |  √   |       |   √   |        |   √   |
| 加密主公钥           |      |        |  √   |       |   √    |       |   √   |
| 用户签名私钥         | √    |        |      |       |        |       |       |
| 用户加密私钥         |      |        |      |   √   |        |   √   |   √   |
| 用户 ID             |      | √      |      |   √   |         |  √   |   √   |

对于 KGC 而言, 在生成用户私钥时, 需要私钥生成标识符和主私钥.

## ZUC 序列密码算法

ZUC 是一种序列密码, 它用于生成伪随机密钥流, 后续可以使用生成的密钥流与明文数据进行异或加密.

常见的序列密码还有 RC4, 但考虑到安全问题现已逐渐弃用.

在 gmalg 中实现的 ZUC 算法并不包含加密和解密功能, 只提供了密钥流的生成功能, 用户可以自定义密钥流的用途与加解密的方式.

---

按如下方式使用 ZUC 算法来生成伪随机密钥流.

```python
import gmalg

key = bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b")
iv = bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766")
zuc = gmalg.ZUC(key, iv)

k = zuc.generate()
print(k.hex())

k = zuc.generate()
print(k.hex())
```

[`ZUC`][gmalg.ZUC] 需要提供 `key` 和 `iv` 两个参数, 长度均为 16 字节, 使用 [`generate`][gmalg.ZUC] 方法可以生成伪随机数据流, 每次生成的数据长度为 4 字节.
