# -*- coding: utf-8 -*-
"""
example_sm3.py - SM3 密码杂凑算法调用示例

演示 SM3 的完整使用流程:
  1. SM3 哈希 (基础 + 流式)
  2. SM3 HMAC
  3. SM3 KDF (密钥派生)
  4. SM3 PBKDF2 (基于口令的密钥派生)
  5. SM3 块压缩
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gmllc import gmssl, rand_bytes
from gmllc import sm3

print("=" * 60)
print("SM3 密码杂凑算法 - GmLLC 调用示例")
print("=" * 60)

# ============================================================
# 1. SM3 哈希
# ============================================================
print("\n--- 1. SM3 哈希 ---")

# 1a. 基础哈希
message = b"Hello, SM3! This is a test message for SM3 hash function."
ctx = sm3.sm3_init()
sm3.sm3_update(ctx, message)
dgst = sm3.sm3_finish(ctx)
print(f"  SM3({message!r}) = {dgst.hex()}")

# 1b. 流式哈希
ctx = sm3.sm3_init()
sm3.sm3_update(ctx, b"Hello, ")
sm3.sm3_update(ctx, b"SM3! ")
sm3.sm3_update(ctx, b"This is a test message for SM3 hash function.")
dgst2 = sm3.sm3_finish(ctx)
print(f"  流式SM3 = {dgst2.hex()}")
print(f"  结果一致: {dgst == dgst2}")

# 1c. 便捷类 Sm3
sm3_obj = sm3.Sm3()
sm3_obj.update(b"Hello, ")
sm3_obj.update(b"SM3!")
dgst3 = sm3_obj.digest()
print(f"  Sm3类: {dgst3.hex()}")

# 1d. 上下文复制
sm3_obj2 = sm3.Sm3()
sm3_obj2.update(b"Hello, ")
sm3_copied = sm3_obj2.copy()
sm3_obj2.update(b"World!")
sm3_copied.update(b"SM3!")
dgst_a = sm3_obj2.digest()
dgst_b = sm3_copied.digest()
print(f"  上下文复制: SM3(Hello, World!) = {dgst_a.hex()}")
print(f"  上下文复制: SM3(Hello, SM3!) = {dgst_b.hex()}")

# 1e. 空消息
ctx = sm3.sm3_init()
empty_dgst = sm3.sm3_finish(ctx)
print(f"  SM3('') = {empty_dgst.hex()}")

# ============================================================
# 2. SM3 HMAC
# ============================================================
print("\n--- 2. SM3 HMAC ---")

key = b"my-secret-hmac-key-1234567890"
message = b"Important message to authenticate"

# 2a. 基础HMAC
ctx = sm3.sm3_hmac_init(key)
sm3.sm3_hmac_update(ctx, message)
hmac_val = sm3.sm3_hmac_finish(ctx)
print(f"  SM3-HMAC = {hmac_val.hex()}")

# 2b. 不同密钥产生不同HMAC
key2 = b"another-secret-key-1234567890"
ctx = sm3.sm3_hmac_init(key2)
sm3.sm3_hmac_update(ctx, message)
hmac_val2 = sm3.sm3_hmac_finish(ctx)
print(f"  SM3-HMAC(key2) = {hmac_val2.hex()}")
print(f"  HMAC不同: {hmac_val != hmac_val2}")

# 2c. 便捷类 Sm3Hmac
hmac_obj = sm3.Sm3Hmac(key)
hmac_obj.update(message)
hmac_val3 = hmac_obj.generate_mac()
print(f"  Sm3Hmac类: {hmac_val3.hex()}")
print(f"  HMAC一致: {hmac_val == hmac_val3}")

# ============================================================
# 3. SM3 KDF (密钥派生)
# ============================================================
print("\n--- 3. SM3 KDF (密钥派生) ---")

# 3a. 基础KDF
kdf_input = b"shared-secret-material"
kdf_outlen = 48  # 派生48字节密钥

ctx = sm3.sm3_kdf_init(kdf_outlen)
sm3.sm3_kdf_update(ctx, kdf_input)
derived_key = sm3.sm3_kdf_finish(ctx)
print(f"  KDF输出({kdf_outlen}字节): {derived_key.hex()}")

# 3b. 不同长度的派生
ctx = sm3.sm3_kdf_init(16)
sm3.sm3_kdf_update(ctx, kdf_input)
key_16 = sm3.sm3_kdf_finish(ctx)
print(f"  KDF输出(16字节): {key_16.hex()}")

ctx = sm3.sm3_kdf_init(64)
sm3.sm3_kdf_update(ctx, kdf_input)
key_64 = sm3.sm3_kdf_finish(ctx)
print(f"  KDF输出(64字节): {key_64.hex()[:32]}...")

# 3c. 便捷类 Sm3Kdf
kdf_obj = sm3.Sm3Kdf(32)
kdf_obj.update(kdf_input)
key_32 = kdf_obj.finish()
print(f"  Sm3Kdf(32): {key_32.hex()}")

# ============================================================
# 4. SM3 PBKDF2 (基于口令的密钥派生)
# ============================================================
print("\n--- 4. SM3 PBKDF2 ---")

password = "my-secure-password"
salt = rand_bytes(8)
iterations = 10000
keylen = 32

derived = sm3.sm3_pbkdf2(password, salt, iterations, keylen)
print(f"  口令: '{password}'")
print(f"  Salt: {salt.hex()}")
print(f"  迭代次数: {iterations}")
print(f"  派生密钥: {derived.hex()}")

# 同一参数产生相同密钥
derived2 = sm3.sm3_pbkdf2(password, salt, iterations, keylen)
print(f"  确定性: {derived == derived2}")

# 不同salt产生不同密钥
salt2 = rand_bytes(8)
derived3 = sm3.sm3_pbkdf2(password, salt2, iterations, keylen)
print(f"  不同salt: {derived != derived3}")

# ============================================================
# 5. SM3 块压缩
# ============================================================
print("\n--- 5. SM3 块压缩 ---")

# SM3块压缩: 直接压缩64字节块
initial_digest = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                  0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]  # 标准IV
block = bytes(64)  # 全零块
sm3.sm3_compress_blocks(initial_digest, block, 1)
print(f"  压缩后digest[0]: 0x{initial_digest[0]:08X}")

# ============================================================
# 6. SM3 DIGEST (通用摘要接口) - 注：DLL版本在退出时崩溃，直接调用可正常工作
# ============================================================
print("\n--- 6. SM3 DIGEST (通用接口) ---")
print("  SM3 DIGEST: 跳过（DLL版本在退出时存在已知崩溃问题，独立调用功能正常）")

# 验证空消息SM3
expected_empty = bytes.fromhex(
    "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B")
print(f"  SM3('') 标准值验证: {empty_dgst == expected_empty}")

print("\n" + "=" * 60)
print("SM3 示例全部完成!")
print("=" * 60)