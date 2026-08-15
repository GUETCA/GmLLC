# -*- coding: utf-8 -*-
"""
example_sm4.py - SM4 分组密码调用示例

演示 SM4 的完整使用流程:
  1. ECB 模式 (单块 + 批量)
  2. CBC 模式 (流式 + Padding)
  3. CTR / CTR32 模式
  4. GCM 模式 (AEAD认证加密)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gmllc import gmssl, rand_bytes
from gmllc import sm4

print("=" * 60)
print("SM4 分组密码 - GmLLC 调用示例")
print("=" * 60)

# ============================================================
# 1. ECB 模式
# ============================================================
print("\n--- 1. SM4 ECB 模式 ---")

key = rand_bytes(sm4.SM4_KEY_SIZE)
print(f"  密钥: {key.hex()}")

enc_key = sm4.sm4_set_encrypt_key(key)
dec_key = sm4.sm4_set_decrypt_key(key)

# 1a. 单块加密
block = b"Hello SM4 ECB!!!"  # 正好16字节
ct = sm4.sm4_encrypt(enc_key, block)
print(f"  单块加密: {block!r} → {ct.hex()}")

pt = sm4.sm4_encrypt(dec_key, ct)
print(f"  单块解密: {pt}")

# 1b. 批量加密
data = b"A" * 64  # 4个块
ct_blocks = sm4.sm4_encrypt_blocks(enc_key, data)
print(f"  批量加密: {len(data)}字节 → {len(ct_blocks)}字节")

# 1c. 便捷类
ecb = sm4.Sm4Ecb(key, encrypt=True)
ct2 = ecb.encrypt(block)
print(f"  Sm4Ecb: {ct2.hex()}")
print(f"  ECB一致: {ct == ct2}")

# ============================================================
# 2. CBC 模式
# ============================================================
print("\n--- 2. SM4 CBC 模式 ---")

iv = rand_bytes(sm4.SM4_BLOCK_SIZE)
plaintext = b"SM4 CBC mode encryption test with padding!"

# 2a. CBC Padding加密
ct_cbc = sm4.sm4_cbc_padding_encrypt(enc_key, iv, plaintext)
print(f"  CBC Padding加密: 明文{len(plaintext)}字节 → 密文{len(ct_cbc)}字节")

# 2b. CBC Padding解密
pt_cbc = sm4.sm4_cbc_padding_decrypt(dec_key, iv, ct_cbc)
print(f"  CBC Padding解密: {pt_cbc}")
print(f"  CBC正确: {pt_cbc == plaintext}")

# 2c. 流式CBC加密
cbc_enc = sm4.Sm4Cbc(key, iv, encrypt=True)
ct1 = cbc_enc.update(b"SM4 CBC ")
ct2 = cbc_enc.update(b"mode encryption ")
ct3 = cbc_enc.update(b"test with padding!")
ct4 = cbc_enc.finish()
ct_stream = ct1 + ct2 + ct3 + ct4
print(f"  流式CBC加密: {len(ct_stream)}字节")

# 2d. 流式CBC解密（注意：CBC流式解密update/finish处理PKCS#7填充，
#     需要将密文分块传入，最后一个块留给finish处理）
cbc_dec = sm4.Sm4Cbc(key, iv, encrypt=False)
pt1 = cbc_dec.update(ct1)
pt2 = cbc_dec.update(ct2)
pt3 = cbc_dec.update(ct3 + ct4)  # 最后一块+padding一起传入
pt4 = cbc_dec.finish()
pt_stream = pt1 + pt2 + pt3 + pt4
print(f"  流式CBC解密: {pt_stream}")
print(f"  流式CBC正确: {pt_stream == plaintext}")

# 2e. 批量块CBC加密
data_blocks = b"A" * 64
iv2 = rand_bytes(sm4.SM4_BLOCK_SIZE)
iv_after, ct_cbc_blocks = sm4.sm4_cbc_encrypt_blocks(enc_key, iv2, data_blocks)
print(f"  批量CBC加密: {len(data_blocks)}字节 → {len(ct_cbc_blocks)}字节")

# 解密
iv_after2, pt_cbc_blocks = sm4.sm4_cbc_decrypt_blocks(dec_key, iv2, ct_cbc_blocks)
print(f"  批量CBC解密正确: {pt_cbc_blocks == data_blocks}")

# ============================================================
# 3. CTR / CTR32 模式
# ============================================================
print("\n--- 3. SM4 CTR 模式 ---")

ctr = bytes(16)  # 全零计数器
plaintext = b"SM4 CTR mode encryption!"

# 3a. CTR流式加密
ctr_enc = sm4.Sm4Ctr(key, ctr)
ct_ctr = ctr_enc.update(plaintext)
ct_ctr_fin = ctr_enc.finish()
print(f"  CTR加密: {len(ct_ctr + ct_ctr_fin)}字节")

# CTR解密 (相同操作)
ctr_dec = sm4.Sm4Ctr(key, ctr)
pt_ctr = ctr_dec.update(ct_ctr + ct_ctr_fin)
pt_ctr_fin = ctr_dec.finish()
print(f"  CTR解密正确: {pt_ctr + pt_ctr_fin == plaintext}")

# 3b. CTR批量加密
ctr2 = bytes(16)
data_ctr = b"A" * 64
ctr_after, ct_batch = sm4.sm4_ctr_encrypt_blocks(enc_key, ctr2, data_ctr)
print(f"  批量CTR加密: {len(data_ctr)}字节 → {len(ct_batch)}字节")

# 3c. CTR32流式加密
ctr32_ctx = sm4.sm4_ctr32_encrypt_init(key, bytes(16))
ct32 = sm4.sm4_ctr32_encrypt_update(ctr32_ctx, plaintext)
ct32_fin = sm4.sm4_ctr32_encrypt_finish(ctr32_ctx)
print(f"  CTR32加密: {len(ct32 + ct32_fin)}字节")

# ============================================================
# 4. GCM 模式 (AEAD认证加密)
# ============================================================
print("\n--- 4. SM4 GCM 模式 (AEAD) ---")

gcm_iv = rand_bytes(sm4.SM4_GCM_DEFAULT_IV_SIZE)
aad = b"Additional Authenticated Data"
plaintext = b"Secret message protected by SM4-GCM"
taglen = sm4.SM4_GCM_DEFAULT_TAG_SIZE

# 4a. GCM一次性加密
ct_gcm, tag = sm4.sm4_gcm_encrypt(enc_key, gcm_iv, aad, plaintext, taglen)
print(f"  GCM加密: 明文{len(plaintext)}字节 → 密文{len(ct_gcm)}字节 + 标签{len(tag)}字节")
print(f"  GCM标签: {tag.hex()}")

# 4b. GCM一次性解密
pt_gcm = sm4.sm4_gcm_decrypt(enc_key, gcm_iv, aad, ct_gcm, tag)
print(f"  GCM解密正确: {pt_gcm == plaintext}")

# 4c. 错误标签验证
wrong_tag = bytes(16)
try:
    pt_gcm = sm4.sm4_gcm_decrypt(enc_key, gcm_iv, aad, ct_gcm, wrong_tag)
    print(f"  GCM错误标签: 解密成功(不应该!)")
except Exception as e:
    print(f"  GCM错误标签: 正确拒绝 - {e}")

# 4d. 流式GCM加密
gcm_enc = sm4.Sm4Gcm(key, gcm_iv, aad, taglen, encrypt=True)
gcm_ct1 = gcm_enc.update(b"Secret ")
gcm_ct2 = gcm_enc.update(b"message ")
gcm_ct3 = gcm_enc.update(b"protected by SM4-GCM")
gcm_ct4 = gcm_enc.finish()  # 最后一段包含认证标签
gcm_ct_full = gcm_ct1 + gcm_ct2 + gcm_ct3 + gcm_ct4
print(f"  流式GCM加密: {len(gcm_ct_full)}字节")

# 4e. 流式GCM解密（注意：GCM加密的finish()产生的数据包含认证标签，
#     解密时需要将所有数据（包括标签）传给update，finish()负责验证标签）
gcm_dec = sm4.Sm4Gcm(key, gcm_iv, aad, taglen, encrypt=False)
gcm_pt1 = gcm_dec.update(gcm_ct1)
gcm_pt2 = gcm_dec.update(gcm_ct2)
gcm_pt3 = gcm_dec.update(gcm_ct3 + gcm_ct4)  # 连同标签一起传入
gcm_pt4 = gcm_dec.finish()  # 验证标签
gcm_pt_full = gcm_pt1 + gcm_pt2 + gcm_pt3 + gcm_pt4
print(f"  流式GCM解密正确: {gcm_pt_full == plaintext}")

print("\n" + "=" * 60)
print("SM4 示例全部完成!")
print("=" * 60)