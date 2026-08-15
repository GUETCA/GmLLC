# -*- coding: utf-8 -*-
"""
example_sm9.py - SM9 标识密码算法调用示例

演示 SM9 的完整使用流程:
  1. 低层数学接口 (sm9_z256)
  2. 签名/验签 (主密钥生成 → 提取密钥 → 签名 → 验签)
  3. 加密/解密 (主密钥生成 → 提取密钥 → 加密 → 解密)
  4. 密钥交换
  5. 低层 do_sign/do_verify/do_encrypt/do_decrypt
  6. KEM 密钥封装
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gmllc import gmssl, rand_bytes
from gmllc import sm9, sm9_z256

print("=" * 60)
print("SM9 标识密码算法 - GmLLC 调用示例")
print("=" * 60)
sys.stdout.flush()

# ============================================================
# 1. 低层数学接口演示 (sm9_z256)
# ============================================================
print("\n--- 1. SM9 Z256 低层数学 ---")

# 获取SM9曲线参数
prime = sm9_z256.z256_prime()
order = sm9_z256.z256_order()
print(f"SM9 素数 p: {sm9_z256.z256_to_hex(prime)[:32]}...")
print(f"SM9 群阶 n: {sm9_z256.z256_to_hex(order)[:32]}...")

# 基本运算
a = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
b = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000002")
c = sm9_z256.z256_modp_add(a, b)
print(f"  modp_add(1, 2) = {sm9_z256.z256_to_hex(c)[:16]}...")

# Fp2 运算
fp2_a = sm9_z256.fp2_set_one()
fp2_b = sm9_z256.fp2_rand()
fp2_c = sm9_z256.fp2_add(fp2_a, fp2_b)
print(f"  fp2_is_one(fp2_a) = {sm9_z256.fp2_is_one(fp2_a)}")

# 椭圆曲线点
P1 = sm9_z256.z256_generator()
print(f"  G1 生成元: is_on_curve = {sm9_z256.z256_point_is_on_curve(P1)}")
P2 = sm9_z256.z256_twist_generator()
print(f"  G2 生成元: is_on_curve = {sm9_z256.z256_twist_point_is_on_curve(P2)}")

# 点运算
R = sm9_z256.z256_point_dbl(P1)
print(f"  2*P1: is_on_curve = {sm9_z256.z256_point_is_on_curve(R)}")

# 配对运算
print("  计算配对 e(P2, P1)...")
pairing = sm9_z256.z256_pairing(P2, P1)
hex_result = sm9_z256.fp12_to_hex(pairing)[:40]
print(f"  e(P2, P1) = {hex_result}...")
sys.stdout.flush()

# ============================================================
# 2. SM9 签名/验签
# ============================================================
print("\n--- 2. SM9 签名/验签 ---")

# 2a. 生成签名主密钥
sign_master = sm9.sm9_sign_master_key_generate()
print("  签名主密钥生成成功")

# 2b. 提取用户签名密钥
user_id = "alice@example.com"
sign_key = sm9.sm9_sign_master_key_extract_key(sign_master, user_id)
print(f"  用户 '{user_id}' 签名密钥提取成功")

# 2c. 流式签名
message = b"Hello, SM9! This is a test message for signature."
ctx = sm9.sm9_sign_init()
sm9.sm9_sign_update(ctx, message)
signature = sm9.sm9_sign_finish(ctx, sign_key)
print(f"  签名完成: 长度={len(signature)}字节")

# 2d. 流式验签
ctx = sm9.sm9_verify_init()
sm9.sm9_verify_update(ctx, message)
result = sm9.sm9_verify_finish(ctx, signature, sign_master, user_id)
print(f"  验签结果: {'成功' if result else '失败'}")

# 2e. 低层签名 (do_sign/do_verify)
from gmllc.sm3 import sm3_init, sm3_update, sm3_finish
sm3_ctx = sm3_init()
sm3_update(sm3_ctx, message)
dsgst = sm3_finish(sm3_ctx)
sig_struct = sm9.sm9_do_sign(sign_key, sm3_ctx)
print(f"  do_sign: h={sm9_z256.z256_to_hex(sig_struct.h)[:16]}...")

result = sm9.sm9_do_verify(sign_master, user_id, sm3_ctx, sig_struct)
print(f"  do_verify: {'成功' if result else '失败'}")

# 2f. SM9_HASH1
h1 = sm9.sm9_z256_hash1(user_id, sm9.SM9_HID_SIGN)
print(f"  H1(ID, 0x01) = {sm9_z256.z256_to_hex(h1)[:16]}...")
sys.stdout.flush()

# ============================================================
# 3. SM9 加密/解密
# ============================================================
print("\n--- 3. SM9 加密/解密 ---")

# 3a. 生成加密主密钥
enc_master = sm9.sm9_enc_master_key_generate()
print("  加密主密钥生成成功")

# 3b. 提取用户加密密钥
enc_key = sm9.sm9_enc_master_key_extract_key(enc_master, user_id)
print(f"  用户 '{user_id}' 加密密钥提取成功")

# 3c. 加密
plaintext = b"SM9 encryption test data"
ciphertext = sm9.sm9_encrypt(enc_master, user_id, plaintext)
print(f"  加密完成: 明文{len(plaintext)}字节 → 密文{len(ciphertext)}字节")

# 3d. 解密
decrypted = sm9.sm9_decrypt(enc_key, user_id, ciphertext)
print(f"  解密结果: {decrypted}")
print(f"  解密正确: {decrypted == plaintext}")

# 3e. 低层加解密
C1, c2, c3 = sm9.sm9_do_encrypt(enc_master, user_id, plaintext)
print(f"  do_encrypt: C1点, c2={len(c2)}字节, c3={len(c3)}字节")

decrypted2 = sm9.sm9_do_decrypt(enc_key, user_id, C1, c2, c3)
print(f"  do_decrypt: {decrypted2}")
print(f"  do_decrypt正确: {decrypted2 == plaintext}")

# 3f. KEM 密钥封装
klen = 32
kbuf, C = sm9.sm9_kem_encrypt(enc_master, user_id, klen)
print(f"  KEM加密: 封装密钥={kbuf.hex()[:16]}...")

kbuf2 = sm9.sm9_kem_decrypt(enc_key, user_id, C, klen)
print(f"  KEM解密: 密钥匹配={kbuf == kbuf2}")
sys.stdout.flush()

# ============================================================
# 4. SM9 密钥交换
# ============================================================
print("\n--- 4. SM9 密钥交换 ---")

# 生成交换主密钥 (等同于加密主密钥)
exch_master = sm9.sm9_exch_master_key_generate()
print("  交换主密钥生成成功")

# 提取双方密钥
idA = "alice@example.com"
idB = "bob@example.com"
keyA = sm9.sm9_exch_master_key_extract_key(exch_master, idA)
keyB = sm9.sm9_exch_master_key_extract_key(exch_master, idB)

# 步骤1: A生成RA和rA
RA, rA = sm9.sm9_exch_step_1A(exch_master, idB)
print(f"  Step 1A: RA生成成功")

# 步骤2: B生成RB和共享密钥
RB, skB = sm9.sm9_exch_step_1B(exch_master, idA, idB, keyB, RA)
print(f"  Step 1B: 共享密钥skB={skB.hex()[:16]}...")

# 步骤3: A计算共享密钥
skA = sm9.sm9_exch_step_2A(exch_master, idA, idB, keyA, rA, RA, RB)
print(f"  Step 2A: 共享密钥skA={skA.hex()[:16]}...")
print(f"  密钥一致性: {skA == skB}")
sys.stdout.flush()

# ============================================================
# 5. PEM文件导入导出 (注：DLL版本PEM函数存在兼容性问题，跳过)
# ============================================================
print("\n--- 5. PEM文件导入导出 ---")
print("  PEM编解码: 跳过（DLL版本兼容性问题）")

print("\n" + "=" * 60)
print("SM9 示例全部完成!")
print("=" * 60)

# 注：DLL版本在退出时存在已知崩溃问题（0xC0000005），所有功能测试均正常运行通过。
# 若运行时看不到输出，请使用 python -u example_sm9.py 运行。
sys.stdout.flush()