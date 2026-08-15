# -*- coding: utf-8 -*-
"""
example_sm2.py - SM2 椭圆曲线公钥密码调用示例

演示 SM2 的完整使用流程:
  1. 低层数学接口 (sm2_z256)
  2. 密钥生成与管理
  3. 签名/验签 (流式、底层、快速签名)
  4. 加密/解密 (底层、流式、预计算)
  5. ECDH 密钥交换
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gmllc import gmssl, rand_bytes
from gmllc import sm2, sm2_z256, sm3

print("=" * 60)
print("SM2 椭圆曲线公钥密码 - GmLLC 调用示例")
print("=" * 60)

# ============================================================
# 1. 低层数学接口 (sm2_z256)
# ============================================================
print("\n--- 1. SM2 Z256 低层数学 ---")

# 获取曲线参数
p = sm2_z256.sm2_z256_prime()
n = sm2_z256.sm2_z256_order()
n_minus_1 = sm2_z256.sm2_z256_order_minus_one()
print(f"  SM2 素数 p: {sm2_z256.sm2_z256_to_bytes(p).hex()[:32]}...")
print(f"  SM2 阶 n: {sm2_z256.sm2_z256_to_bytes(n).hex()[:32]}...")

# 基本运算
a = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
b = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000002")
c_add = sm2_z256.sm2_z256_modp_add(a, b)
c_sub = sm2_z256.sm2_z256_modp_sub(b, a)
c_mul = sm2_z256.sm2_z256_modn_mul(a, b)
print(f"  modp_add(1, 2) = {sm2_z256.sm2_z256_to_bytes(c_add).hex()}")
print(f"  modp_sub(2, 1) = {sm2_z256.sm2_z256_to_bytes(c_sub).hex()}")
print(f"  modn_mul(1, 2) = {sm2_z256.sm2_z256_to_bytes(c_mul).hex()}")

# 椭圆曲线点运算
P = sm2_z256.sm2_z256_point_dbl(sm2_z256.SM2_Z256_POINT())  # 2*无穷远=无穷远
infinity = sm2_z256.sm2_z256_point_set_infinity()
print(f"  无穷远点: is_infinity = {sm2_z256.sm2_z256_point_is_at_infinity(infinity)}")

# 从字节构造点
x_bytes = bytes.fromhex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
y_bytes = bytes.fromhex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
point_bytes = x_bytes + y_bytes
P = sm2_z256.sm2_z256_point_from_bytes(point_bytes)
print(f"  点是否在曲线上: {sm2_z256.sm2_z256_point_is_on_curve(P)}")

# 点编码
octets = sm2_z256.sm2_z256_point_to_uncompressed_octets(P)
print(f"  非压缩编码: {octets.hex()[:40]}...")
compressed = sm2_z256.sm2_z256_point_to_compressed_octets(P)
print(f"  压缩编码: {compressed.hex()}")

# 标量乘预计算
pre_table = sm2_z256.sm2_z256_point_mul_pre_compute(P)
k = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
R1 = sm2_z256.sm2_z256_point_mul(k, P)
R2 = sm2_z256.sm2_z256_point_mul_ex(k, pre_table)
print(f"  标量乘结果一致: {sm2_z256.sm2_z256_point_equ(R1, R2)}")

# ============================================================
# 2. 密钥生成与管理
# ============================================================
print("\n--- 2. SM2 密钥生成与管理 ---")

# 生成密钥对
key = sm2.sm2_key_generate()
print("  密钥对生成成功")

# 从私钥设置密钥
key2 = sm2.SM2_KEY()
sm2.sm2_key_set_private_key(key2, key.private_key)
print("  从私钥恢复密钥成功")

# 计算Z值
z = sm2.sm2_compute_z(key.public_key, sm2.SM2_DEFAULT_ID)
print(f"  ZA = {z.hex()}")

# 公钥摘要
pub_dgst = sm2.sm2_public_key_digest(key)
print(f"  公钥摘要: {pub_dgst.hex()[:16]}...")

# 公钥DER编码 (注：该DLL版本的to_der函数存在已知问题，跳过)
print("  公钥/私钥DER/PEM编解码: 跳过（DLL版本兼容性问题）")

# ============================================================
# 3. 签名/验签
# ============================================================
print("\n--- 3. SM2 签名/验签 ---")

message = b"Hello, SM2! This is a test message for signature."

# 3a. 计算SM3摘要
sm3_ctx = sm3.sm3_init()
sm3.sm3_update(sm3_ctx, message)
dgst = sm3.sm3_finish(sm3_ctx)
print(f"  SM3摘要: {dgst.hex()}")

# 3b. 底层签名/验签 (do_sign/do_verify)
r, s = sm2.sm2_do_sign(key, dgst)
print(f"  do_sign: r={r.hex()[:16]}..., s={s.hex()[:16]}...")
result = sm2.sm2_do_verify(key, dgst, r, s)
print(f"  do_verify: {'成功' if result else '失败'}")

# 3c. DER编码签名/验签
sig_der = sm2.sm2_sign(key, dgst)
print(f"  DER签名: {len(sig_der)}字节")
result = sm2.sm2_verify(key, dgst, sig_der)
print(f"  DER验签: {'成功' if result else '失败'}")

# 3d. 流式签名/验签
sign_ctx = sm2.sm2_sign_init(key, sm2.SM2_DEFAULT_ID)
sm2.sm2_sign_update(sign_ctx, b"Hello, ")
sm2.sm2_sign_update(sign_ctx, b"SM2! ")
sm2.sm2_sign_update(sign_ctx, b"This is a test message for signature.")
sig_stream = sm2.sm2_sign_finish(sign_ctx)
print(f"  流式签名: {len(sig_stream)}字节")

verify_ctx = sm2.sm2_verify_init(key, sm2.SM2_DEFAULT_ID)
sm2.sm2_verify_update(verify_ctx, b"Hello, ")
sm2.sm2_verify_update(verify_ctx, b"SM2! ")
sm2.sm2_verify_update(verify_ctx, b"This is a test message for signature.")
result = sm2.sm2_verify_finish(verify_ctx, sig_stream)
print(f"  流式验签: {'成功' if result else '失败'}")

# 3e. 快速签名
fast_priv = sm2.sm2_fast_sign_compute_key(key)
pre_comp = sm2.sm2_fast_sign_pre_compute()
r_fast, s_fast = sm2.sm2_fast_sign(fast_priv, pre_comp, dgst)
print(f"  快速签名: r={r_fast.hex()[:16]}...")

# 3f. 固定长度签名
sig_fixed = sm2.sm2_sign_fixlen(key, dgst, 70)
print(f"  固定长度签名(70字节): {len(sig_fixed)}字节")

# ============================================================
# 4. 加密/解密
# ============================================================
print("\n--- 4. SM2 加密/解密 ---")

plaintext = b"SM2 encryption test"

# 4a. 底层加解密
ct_struct = sm2.sm2_do_encrypt(key, plaintext)
print(f"  do_encrypt: C1.x={bytes(ct_struct.point.x).hex()[:16]}...")

decrypted = sm2.sm2_do_decrypt(key, ct_struct)
print(f"  do_decrypt: {decrypted}")
print(f"  do_decrypt正确: {decrypted == plaintext}")

# 4b. DER编码加解密
ct_der = sm2.sm2_encrypt(key, plaintext)
print(f"  DER加密: 明文{len(plaintext)}字节 → 密文{len(ct_der)}字节")

pt_der = sm2.sm2_decrypt(key, ct_der)
print(f"  DER解密正确: {pt_der == plaintext}")

# 4c. 密文DER编解码 (注：DLL版本to_der函数存在已知问题，跳过)
print(f"  密文DER编解码: 跳过（DLL版本兼容性问题）")

# 4d. 预计算加密
pre_comp_enc = sm2.sm2_encrypt_pre_compute()
ct_ex = sm2.sm2_do_encrypt_ex(key, pre_comp_enc, plaintext)
print(f"  预计算加密: 密文={ct_ex.ciphertext[:ct_ex.ciphertext_size]}")

# 4e. 流式加密
enc_ctx = sm2.sm2_encrypt_init()
sm2.sm2_encrypt_update(enc_ctx, b"SM2 ")
sm2.sm2_encrypt_update(enc_ctx, b"encryption ")
sm2.sm2_encrypt_update(enc_ctx, b"test")
ct_stream = sm2.sm2_encrypt_finish(enc_ctx, key)
print(f"  流式加密: {len(ct_stream)}字节")

dec_ctx = sm2.sm2_decrypt_init()
sm2.sm2_decrypt_update(dec_ctx, ct_stream)
pt_stream = sm2.sm2_decrypt_finish(dec_ctx, key)
print(f"  流式解密正确: {pt_stream == plaintext}")

# ============================================================
# 5. ECDH 密钥交换
# ============================================================
print("\n--- 5. SM2 ECDH 密钥交换 ---")

# 生成双方密钥对
keyA = sm2.sm2_key_generate()
keyB = sm2.sm2_key_generate()

# ECDH: A用自己的私钥和B的公钥计算共享密钥
shared_A = sm2.sm2_do_ecdh(keyA, keyB)
print(f"  ECDH共享密钥(A): {shared_A.hex()}")

# ECDH: B用自己的私钥和A的公钥计算共享密钥
shared_B = sm2.sm2_do_ecdh(keyB, keyA)
print(f"  ECDH共享密钥(B): {shared_B.hex()}")
print(f"  密钥一致性: {shared_A == shared_B}")

# 使用非压缩点
pubB_octets = sm2_z256.sm2_z256_point_to_uncompressed_octets(keyB.public_key)
shared_A2 = sm2.sm2_ecdh(keyA, pubB_octets)
print(f"  ECDH(非压缩点): {shared_A2.hex()}")
print(f"  密钥一致性: {shared_A == shared_A2}")

print("\n" + "=" * 60)
print("SM2 示例全部完成!")
print("=" * 60)