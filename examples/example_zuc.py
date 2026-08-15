# -*- coding: utf-8 -*-
"""
example_zuc.py - ZUC 祖冲之序列密码调用示例

演示 ZUC 的完整使用流程:
  1. ZUC-128 流密码 (基础 + 流式)
  2. ZUC-128 MAC (完整性校验)
  3. ZUC-128 EEA (LTE加密算法)
  4. ZUC-128 EIA (LTE完整性算法)
  5. ZUC-256 流密码
  6. ZUC-256 MAC
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gmllc import gmssl, rand_bytes
from gmllc import zuc

print("=" * 60)
print("ZUC 祖冲之序列密码 - GmLLC 调用示例")
print("=" * 60)

# ============================================================
# 1. ZUC-128 流密码
# ============================================================
print("\n--- 1. ZUC-128 流密码 ---")

key = rand_bytes(zuc.ZUC_KEY_SIZE)
iv = rand_bytes(zuc.ZUC_IV_SIZE)
print(f"  密钥: {key.hex()}")
print(f"  IV:   {iv.hex()}")

# 1a. 基础加密函数
state = zuc.ZUC_STATE()
zuc.zuc_init(state, key, iv)

plaintext = b"Hello, ZUC-128! This is a test message for ZUC stream cipher."
ciphertext = zuc.zuc_encrypt(state, plaintext)
print(f"  基础加密: 明文{len(plaintext)}字节 → 密文{len(ciphertext)}字节")

# 重新初始化并解密
state2 = zuc.ZUC_STATE()
zuc.zuc_init(state2, key, iv)
decrypted = zuc.zuc_encrypt(state2, ciphertext)
print(f"  解密正确: {decrypted == plaintext}")

# 1b. 密钥流生成
state3 = zuc.ZUC_STATE()
zuc.zuc_init(state3, key, iv)
keystream = zuc.zuc_generate_keystream(state3, 10)
print(f"  密钥流(10字): {keystream.hex()}")

# 1c. 单个密钥字
kw = zuc.zuc_generate_keyword(state3)
print(f"  单个密钥字: 0x{kw:08X}")

# 1d. 流式加密接口
zuc_ctx = zuc.Zuc(key, iv)
ct1 = zuc_ctx.update(b"Hello ")
ct2 = zuc_ctx.update(b"World!")
ct3 = zuc_ctx.finish()
ct_full = ct1 + ct2 + ct3
print(f"  流式加密: {len(ct_full)}字节: {ct_full}")

# 解密
zuc_ctx2 = zuc.Zuc(key, iv)
pt1 = zuc_ctx2.update(ct1)
pt2 = zuc_ctx2.update(ct2)
pt3 = zuc_ctx2.finish()
pt_full = pt1 + pt2 + pt3
print(f"  流式解密: {pt_full}")

# ============================================================
# 2. ZUC-128 MAC
# ============================================================
print("\n--- 2. ZUC-128 MAC ---")

mac_key = rand_bytes(zuc.ZUC_KEY_SIZE)
mac_iv = rand_bytes(zuc.ZUC_IV_SIZE)
message = b"Message for ZUC-128 MAC computation"

mac_ctx = zuc.ZUC_MAC_CTX()
zuc.zuc_mac_init(mac_ctx, mac_key, mac_iv)
zuc.zuc_mac_update(mac_ctx, message)
mac_value = zuc.zuc_mac_finish(mac_ctx, message, len(message) * 8)
print(f"  ZUC-128 MAC: {mac_value.hex()}")

# 便捷类
mac_obj = zuc.ZucMac(mac_key, mac_iv)
mac_obj.update(message)
mac_value2 = mac_obj.finish(message, len(message) * 8)
print(f"  ZUC-128 MAC (便捷): {mac_value2.hex()}")
print(f"  MAC一致: {mac_value == mac_value2}")

# ============================================================
# 3. ZUC-128 EEA (LTE加密算法)
# ============================================================
print("\n--- 3. ZUC-128 EEA (LTE加密) ---")

eea_key = rand_bytes(zuc.ZUC_KEY_SIZE)
count = 0x12345678
bearer = 5
direction = 0  # uplink

# 输入数据 (以32位字为单位)
input_bits = 256
input_words = [0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF,
               0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF]

output_words = zuc.zuc_eea_encrypt(input_words, input_bits, eea_key, count, bearer, direction)
print(f"  输入首字: 0x{input_words[0]:08X}")
print(f"  输出首字: 0x{output_words[0]:08X}")

# 解密 (EEA是对称的)
recovered = zuc.zuc_eea_encrypt(output_words, input_bits, eea_key, count, bearer, direction)
print(f"  EEA解密正确: {recovered == input_words}")

# ============================================================
# 4. ZUC-128 EIA (LTE完整性算法)
# ============================================================
print("\n--- 4. ZUC-128 EIA (LTE完整性) ---")

eia_key = rand_bytes(zuc.ZUC_KEY_SIZE)
eia_data = [0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF]
eia_nbits = len(eia_data) * 32

mac = zuc.zuc_eia_generate_mac(eia_data, eia_nbits, eia_key, count, bearer, direction)
print(f"  EIA MAC: 0x{mac:08X}")

# ============================================================
# 5. ZUC-256 流密码
# ============================================================
print("\n--- 5. ZUC-256 流密码 ---")

z256_key = rand_bytes(zuc.ZUC256_KEY_SIZE)
z256_iv = rand_bytes(zuc.ZUC256_IV_SIZE)
print(f"  ZUC-256密钥: {z256_key.hex()}")
print(f"  ZUC-256 IV:   {z256_iv.hex()}")

state256 = zuc.ZUC_STATE()
zuc.zuc256_init(state256, z256_key, z256_iv)

ks256 = zuc.zuc256_generate_keystream(state256, 8)
print(f"  密钥流(8字): {ks256.hex()}")

kw256 = zuc.zuc256_generate_keyword(state256)
print(f"  单个密钥字: 0x{kw256:08X}")

# ============================================================
# 6. ZUC-256 MAC
# ============================================================
print("\n--- 6. ZUC-256 MAC ---")

z256_mac_key = rand_bytes(zuc.ZUC256_KEY_SIZE)
z256_mac_iv = rand_bytes(zuc.ZUC256_IV_SIZE)
z256_message = b"Message for ZUC-256 MAC computation"

# 32位MAC
mac256_ctx = zuc.ZUC256_MAC_CTX()
zuc.zuc256_mac_init(mac256_ctx, z256_mac_key, z256_mac_iv, 32)
zuc.zuc256_mac_update(mac256_ctx, z256_message)
mac32 = zuc.zuc256_mac_finish(mac256_ctx, z256_message, len(z256_message) * 8, 4)
print(f"  ZUC-256 MAC32: {mac32.hex()}")

# 64位MAC
mac256_ctx = zuc.ZUC256_MAC_CTX()
zuc.zuc256_mac_init(mac256_ctx, z256_mac_key, z256_mac_iv, 64)
zuc.zuc256_mac_update(mac256_ctx, z256_message)
mac64 = zuc.zuc256_mac_finish(mac256_ctx, z256_message, len(z256_message) * 8, 8)
print(f"  ZUC-256 MAC64: {mac64.hex()}")

# 128位MAC
mac256_ctx = zuc.ZUC256_MAC_CTX()
zuc.zuc256_mac_init(mac256_ctx, z256_mac_key, z256_mac_iv, 128)
zuc.zuc256_mac_update(mac256_ctx, z256_message)
mac128 = zuc.zuc256_mac_finish(mac256_ctx, z256_message, len(z256_message) * 8, 16)
print(f"  ZUC-256 MAC128: {mac128.hex()}")

# 便捷类
z256_mac_obj = zuc.Zuc256Mac(z256_mac_key, z256_mac_iv, 128)
z256_mac_obj.update(z256_message)
mac128_2 = z256_mac_obj.finish(z256_message, len(z256_message) * 8)
print(f"  ZUC-256 MAC128 (便捷): {mac128_2.hex()}")
print(f"  MAC一致: {mac128 == mac128_2}")

print("\n" + "=" * 60)
print("ZUC 示例全部完成!")
print("=" * 60)