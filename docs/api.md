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

---

::: gmalg.primefield.Fp2Ele
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.primefield.Fp4Ele
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.primefield.Fp12Ele
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.primefield.FpExEle
    options:
        heading_level: 3
        show_root_full_path: false

---

::: gmalg.ellipticcurve

---

::: gmalg.ellipticcurve.EcPoint
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.ellipticcurve.EcPoint2
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.ellipticcurve.EcPoint4
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.ellipticcurve.EcPoint12
    options:
        heading_level: 3
        show_root_full_path: false
::: gmalg.ellipticcurve.EcPointEx
    options:
        heading_level: 3
        show_root_full_path: false

---

::: gmalg.base

---

问题没有得到解决? 不如看看[源码](https://github.com/ww-rm/gmalg)或者[提个 Issue](https://github.com/ww-rm/gmalg/issues).
