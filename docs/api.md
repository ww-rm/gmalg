# API 参考

常用接口已经自动导入 `gmalg` 命名空间, 可以直接使用, 点击下方链接快速跳转至说明.

- [gmalg.SM2][gmalg.sm2.SM2]
- [gmalg.SM3][gmalg.sm3.SM3]
- [gmalg.SM4][gmalg.sm4.SM4]
- [gmalg.SM9KGC][gmalg.sm9.SM9KGC]
- [gmalg.SM9][gmalg.sm9.SM9]
- [gmalg.ZUC][gmalg.zuc.ZUC]
- [gmalg.errors][gmalg.errors]
- [gmalg.KEYXCHG_MODE][gmalg.base.KEYXCHG_MODE]
- [gmalg.PC_MODE][gmalg.base.PC_MODE]

继续向下阅读 `gmalg` 中涉及的所有主要接口及其参数说明.

---

::: gmalg.sm2
    options:
        members:
            - SM2Core
            - SM2
            - point_to_bytes
            - bytes_to_point

---

::: gmalg.sm3
    options:
        members:
            - SM3

---

::: gmalg.sm4
    options:
        members:
            - SM4

---

::: gmalg.sm9
    options:
        members:
            - SM9Core
            - SM9KGC
            - SM9
            - point_to_bytes_1
            - bytes_to_point_1
            - point_to_bytes_2
            - bytes_to_point_2

---

::: gmalg.zuc
    options:
        members:
            - ZUC

---

::: gmalg.errors
    options:
        show_signature: false

---

::: gmalg.primefield
    options:
        members_order: source

---

::: gmalg.ellipticcurve

---

::: gmalg.base

---

问题没有得到解决? 不如看看[源码](https://github.com/ww-rm/gmalg)或者[提个 Issue](https://github.com/ww-rm/gmalg/issues).
