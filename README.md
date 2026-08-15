# GmLLC v1.0.0

基于 GmSSL 3.2.0 DLL 的国密算法低层 Python 接口库，通过 ctypes 直接封装 DLL 导出函数，适用于密码学分析、高效计算、CTF 解题等场景。

## 安装

```bash
pip install ./gmllc
```

或直接使用：

```python
import sys
sys.path.insert(0, "gmllc")
import gmllc
```

## 设计原则

1. 直接封装 DLL 导出函数，不做高层抽象
2. 按模块分类：`sm2`, `sm2_z256`, `sm3`, `sm4`, `sm9`, `sm9_z256`, `zuc`
3. 低级接口直接暴露，允许调用者自由组合

## 快速开始

```python
from gmllc import gmssl, rand_bytes, version_str, __version__
from gmllc import sm2, sm3, sm4

# 查看版本
print(__version__)     # 1.0.0
print(version_str())   # GmSSL 3.2.0

# 生成随机数
key = rand_bytes(16)

# SM3 哈希
ctx = sm3.sm3_init()
sm3.sm3_update(ctx, b"Hello, GmLLC!")
digest = sm3.sm3_finish(ctx)
print(digest.hex())
```

## 模块功能

| 模块         | 算法           | 功能                              |
| ---------- | ------------ | ------------------------------- |
| `sm2`      | SM2 椭圆曲线公钥密码 | 密钥生成、签名/验签、加密/解密、ECDH 密钥交换      |
| `sm2_z256` | SM2 低层数学     | 大整数运算、Fp/Fn 模运算、椭圆曲线点运算         |
| `sm3`      | SM3 密码杂凑     | 哈希、HMAC、KDF、PBKDF2              |
| `sm4`      | SM4 分组密码     | ECB、CBC、CTR、CTR32、GCM 模式        |
| `sm9`      | SM9 标识密码     | 签名/验签、加密/解密、KEM、密钥交换            |
| `sm9_z256` | SM9 低层数学     | Fp/Fp2/Fp4/Fp12 扩域、配对运算、G1/G2 群 |
| `zuc`      | ZUC 祖冲之序列密码  | ZUC-128/256 流密码、MAC、EEA/EIA     |

## 示例

参考 `examples/` 目录下的完整示例：

- `example_sm2.py` — SM2 密钥生成、签名验签、加解密、ECDH
- `example_sm3.py` — SM3 哈希、HMAC、KDF、PBKDF2
- `example_sm4.py` — SM4 ECB/CBC/CTR/GCM 各模式
- `example_sm9.py` — SM9 签名验签、加解密、KEM、密钥交换
- `example_zuc.py` — ZUC-128/256 流密码、MAC、EEA/EIA

运行示例：

```bash
cd gmllc
python examples/example_sm3.py
```

## 测试

```bash
cd gmllc
python test_all.py
```

## 依赖

- Python 3.11+
- `gmssl.dll`（GmSSL 3.2.0，已包含在项目中）

## 许可证

Copyright 2026 The GmLLC Project. All Rights Reserved.