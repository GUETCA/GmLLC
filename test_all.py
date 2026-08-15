# -*- coding: utf-8 -*-
"""
test_all.py - GmLLC 库全面功能测试

覆盖所有模块的核心功能：
  SM2, SM3, SM4, SM9, ZUC, sm2_z256, sm9_z256
"""

import sys
import os
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gmllc import gmssl, rand_bytes, version_num, version_str, GMLLC_VERSION
from gmllc import sm2, sm2_z256, sm3, sm4, sm9, sm9_z256, zuc
from gmllc.error import GmLLCError, NativeError, StateError

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0
FAIL_DETAILS = []


def test(name):
    """装饰器：记录测试结果"""
    def decorator(func):
        def wrapper():
            global PASS_COUNT, FAIL_COUNT, SKIP_COUNT
            try:
                func()
                PASS_COUNT += 1
                print(f"  [PASS] {name}")
            except Exception as e:
                FAIL_COUNT += 1
                msg = f"  [FAIL] {name}: {e}"
                print(msg)
                FAIL_DETAILS.append(f"{name}\n  {traceback.format_exc().strip()}")
            sys.stdout.flush()
        return wrapper
    return decorator


# ============================================================
# 基础库信息
# ============================================================
@test("库版本信息")
def test_version():
    v = version_num()
    assert v > 0, f"版本号异常: {v}"
    s = version_str()
    assert isinstance(s, str) and len(s) > 0, f"版本字符串异常: {s}"
    print(f"    GmLLC: {GMLLC_VERSION}, GmSSL: {s}")

@test("rand_bytes 随机数生成")
def test_rand_bytes():
    r1 = rand_bytes(32)
    r2 = rand_bytes(32)
    assert len(r1) == 32
    assert len(r2) == 32
    assert r1 != r2, "两次随机数不应相同"


# ============================================================
# SM3 哈希
# ============================================================
@test("SM3 基本哈希")
def test_sm3_basic():
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"Hello, SM3!")
    dgst = sm3.sm3_finish(ctx)
    assert len(dgst) == 32, f"摘要长度应为32，实际{len(dgst)}"

@test("SM3 空消息")
def test_sm3_empty():
    expected = bytes.fromhex("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B")
    ctx = sm3.sm3_init()
    dgst = sm3.sm3_finish(ctx)
    assert dgst == expected, f"空消息SM3值不匹配: {dgst.hex()}"

@test("SM3 流式哈希一致性")
def test_sm3_streaming():
    msg = b"Hello, SM3! This is a test message."
    # 一次性
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, msg)
    d1 = sm3.sm3_finish(ctx)
    # 流式
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, msg[:10])
    sm3.sm3_update(ctx, msg[10:])
    d2 = sm3.sm3_finish(ctx)
    assert d1 == d2, "流式哈希与一次性哈希不一致"

@test("SM3 便捷类 Sm3")
def test_sm3_class():
    obj = sm3.Sm3()
    obj.update(b"Hello")
    obj.update(b" World")
    d = obj.digest()
    assert len(d) == 32

@test("SM3 便捷类 reset")
def test_sm3_reset():
    obj = sm3.Sm3()
    obj.update(b"test1")
    d1 = obj.digest()
    obj.reset()
    obj.update(b"test2")
    d2 = obj.digest()
    assert d1 != d2, "reset后应产生不同摘要"

@test("SM3 上下文复制")
def test_sm3_copy():
    obj1 = sm3.Sm3()
    obj1.update(b"prefix-")
    obj2 = obj1.copy()
    obj1.update(b"AAA")
    obj2.update(b"BBB")
    assert obj1.digest() != obj2.digest(), "复制后应独立"

@test("SM3 HMAC")
def test_sm3_hmac():
    key = b"my-secret-key-12345"
    msg = b"Important message"
    ctx = sm3.sm3_hmac_init(key)
    sm3.sm3_hmac_update(ctx, msg)
    mac = sm3.sm3_hmac_finish(ctx)
    assert len(mac) == 32

@test("SM3 HMAC 不同密钥结果不同")
def test_sm3_hmac_diff_key():
    msg = b"same message"
    ctx1 = sm3.sm3_hmac_init(b"key-one-1234567890")
    sm3.sm3_hmac_update(ctx1, msg)
    m1 = sm3.sm3_hmac_finish(ctx1)
    ctx2 = sm3.sm3_hmac_init(b"key-two-1234567890")
    sm3.sm3_hmac_update(ctx2, msg)
    m2 = sm3.sm3_hmac_finish(ctx2)
    assert m1 != m2, "不同密钥应产生不同HMAC"

@test("SM3 HMAC 便捷类")
def test_sm3_hmac_class():
    key = b"key-for-hmac-class"
    msg = b"test message"
    obj = sm3.Sm3Hmac(key)
    obj.update(msg)
    mac = obj.generate_mac()
    assert len(mac) == 32

@test("SM3 KDF")
def test_sm3_kdf():
    ctx = sm3.sm3_kdf_init(32)
    sm3.sm3_kdf_update(ctx, b"secret-material")
    key = sm3.sm3_kdf_finish(ctx)
    assert len(key) == 32

@test("SM3 KDF 不同长度")
def test_sm3_kdf_len():
    ctx16 = sm3.sm3_kdf_init(16)
    sm3.sm3_kdf_update(ctx16, b"test")
    k16 = sm3.sm3_kdf_finish(ctx16)
    ctx48 = sm3.sm3_kdf_init(48)
    sm3.sm3_kdf_update(ctx48, b"test")
    k48 = sm3.sm3_kdf_finish(ctx48)
    assert len(k16) == 16
    assert len(k48) == 48

@test("SM3 PBKDF2")
def test_sm3_pbkdf2():
    key = sm3.sm3_pbkdf2("password", b"12345678", 10000, 32)
    assert len(key) == 32

@test("SM3 PBKDF2 确定性")
def test_sm3_pbkdf2_deterministic():
    k1 = sm3.sm3_pbkdf2("password", b"12345678", 10000, 32)
    k2 = sm3.sm3_pbkdf2("password", b"12345678", 10000, 32)
    assert k1 == k2, "相同参数应产生相同密钥"

@test("SM3 DIGEST 通用接口")
def test_sm3_digest():
    ctx = sm3.sm3_digest_init()
    sm3.sm3_digest_update(ctx, b"Hello")
    dgst = sm3.sm3_digest_finish(ctx)
    assert len(dgst) == 32

@test("SM3 块压缩")
def test_sm3_compress_blocks():
    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    sm3.sm3_compress_blocks(iv, bytes(64), 1)
    assert iv[0] != 0x7380166F, "压缩后digest应改变"


# ============================================================
# SM4 分组密码
# ============================================================
@test("SM4 基本加密解密")
def test_sm4_basic():
    key = rand_bytes(16)
    block = b"Hello SM4 ECB!!!"  # 16字节
    enc_key = sm4.sm4_set_encrypt_key(key)
    dec_key = sm4.sm4_set_decrypt_key(key)
    ct = sm4.sm4_encrypt(enc_key, block)
    pt = sm4.sm4_encrypt(dec_key, ct)
    assert pt == block, f"SM4加解密不匹配: {pt} != {block}"

@test("SM4 ECB 批量加密")
def test_sm4_ecb_blocks():
    key = rand_bytes(16)
    enc_key = sm4.sm4_set_encrypt_key(key)
    data = b"A" * 64
    ct = sm4.sm4_encrypt_blocks(enc_key, data)
    assert len(ct) == 64

@test("SM4 CBC Padding 加解密")
def test_sm4_cbc_padding():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    pt = b"SM4 CBC mode test with padding data!"
    enc_key = sm4.sm4_set_encrypt_key(key)
    dec_key = sm4.sm4_set_decrypt_key(key)
    ct = sm4.sm4_cbc_padding_encrypt(enc_key, iv, pt)
    pt2 = sm4.sm4_cbc_padding_decrypt(dec_key, iv, ct)
    assert pt2 == pt, f"SM4 CBC Padding解密不匹配"

@test("SM4 CBC 批量块加解密")
def test_sm4_cbc_blocks():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    data = b"A" * 64
    enc_key = sm4.sm4_set_encrypt_key(key)
    dec_key = sm4.sm4_set_decrypt_key(key)
    iv_after, ct = sm4.sm4_cbc_encrypt_blocks(enc_key, iv, data)
    iv_after2, pt = sm4.sm4_cbc_decrypt_blocks(dec_key, iv, ct)
    assert pt == data, "CBC批量解密不匹配"

@test("SM4 CBC 流式加解密")
def test_sm4_cbc_streaming():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    pt = b"SM4 CBC streaming encryption test with padding!"
    cbc_enc = sm4.Sm4Cbc(key, iv, encrypt=True)
    ct1 = cbc_enc.update(pt[:10])
    ct2 = cbc_enc.update(pt[10:])
    ct3 = cbc_enc.finish()
    ct = ct1 + ct2 + ct3
    cbc_dec = sm4.Sm4Cbc(key, iv, encrypt=False)
    pt1 = cbc_dec.update(ct)
    pt2 = cbc_dec.finish()
    pt_full = pt1 + pt2
    assert pt_full == pt, f"CBC流式解密不匹配"

@test("SM4 CTR 流式加解密")
def test_sm4_ctr():
    key = rand_bytes(16)
    ctr = bytes(16)
    pt = b"SM4 CTR mode encryption test!"
    ctr_enc = sm4.Sm4Ctr(key, ctr)
    ct = ctr_enc.update(pt) + ctr_enc.finish()
    ctr_dec = sm4.Sm4Ctr(key, ctr)
    pt2 = ctr_dec.update(ct) + ctr_dec.finish()
    assert pt2 == pt, "CTR解密不匹配"

@test("SM4 CTR 批量加密")
def test_sm4_ctr_blocks():
    key = rand_bytes(16)
    ctr = bytes(16)
    data = b"A" * 64
    enc_key = sm4.sm4_set_encrypt_key(key)
    ctr_after, ct = sm4.sm4_ctr_encrypt_blocks(enc_key, ctr, data)
    assert len(ct) == 64

@test("SM4 CTR32 流式加密")
def test_sm4_ctr32():
    key = rand_bytes(16)
    pt = b"SM4 CTR32 test message data!"
    ctx = sm4.sm4_ctr32_encrypt_init(key, bytes(16))
    ct = sm4.sm4_ctr32_encrypt_update(ctx, pt)
    ct_fin = sm4.sm4_ctr32_encrypt_finish(ctx)
    assert len(ct) + len(ct_fin) == len(pt)

@test("SM4 GCM 加解密")
def test_sm4_gcm():
    key = rand_bytes(16)
    iv = rand_bytes(12)
    aad = b"Additional Auth Data"
    pt = b"Secret message for GCM"
    enc_key = sm4.sm4_set_encrypt_key(key)
    ct, tag = sm4.sm4_gcm_encrypt(enc_key, iv, aad, pt, 16)
    pt2 = sm4.sm4_gcm_decrypt(enc_key, iv, aad, ct, tag)
    assert pt2 == pt, "GCM解密不匹配"

@test("SM4 GCM 错误标签拒绝")
def test_sm4_gcm_wrong_tag():
    key = rand_bytes(16)
    iv = rand_bytes(12)
    aad = b"AAD"
    pt = b"test message"
    enc_key = sm4.sm4_set_encrypt_key(key)
    ct, tag = sm4.sm4_gcm_encrypt(enc_key, iv, aad, pt, 16)
    try:
        sm4.sm4_gcm_decrypt(enc_key, iv, aad, ct, bytes(16))
        assert False, "错误标签应该被拒绝"
    except NativeError:
        pass  # 预期行为

@test("SM4 GCM 流式加解密")
def test_sm4_gcm_streaming():
    key = rand_bytes(16)
    iv = rand_bytes(12)
    aad = b"Streaming AAD"
    pt = b"Streaming GCM test message data!"
    taglen = 16
    gcm_enc = sm4.Sm4Gcm(key, iv, aad, taglen, encrypt=True)
    ct1 = gcm_enc.update(pt[:10])
    ct2 = gcm_enc.update(pt[10:])
    ct3 = gcm_enc.finish()
    ct = ct1 + ct2 + ct3
    gcm_dec = sm4.Sm4Gcm(key, iv, aad, taglen, encrypt=False)
    pt1 = gcm_dec.update(ct)
    pt2 = gcm_dec.finish()
    pt_full = pt1 + pt2
    assert pt_full == pt, "GCM流式解密不匹配"

@test("SM4 便捷类 Sm4Ecb")
def test_sm4_ecb_class():
    key = rand_bytes(16)
    ecb = sm4.Sm4Ecb(key, encrypt=True)
    ct = ecb.encrypt(b"Hello SM4 ECB!!!")
    assert len(ct) == 16

@test("SM4 密钥长度校验")
def test_sm4_key_len():
    try:
        sm4.sm4_set_encrypt_key(b"short")
        assert False, "应该拒绝短密钥"
    except ValueError:
        pass


# ============================================================
# SM2 椭圆曲线公钥密码
# ============================================================
@test("SM2 密钥生成")
def test_sm2_keygen():
    key = sm2.sm2_key_generate()
    assert key is not None

@test("SM2 从私钥恢复密钥")
def test_sm2_set_private():
    key1 = sm2.sm2_key_generate()
    key2 = sm2.SM2_KEY()
    sm2.sm2_key_set_private_key(key2, key1.private_key)
    # 验证公钥相同
    assert sm2.sm2_public_key_equ(key1, key2) == 1

@test("SM2 公钥摘要")
def test_sm2_pubkey_digest():
    key = sm2.sm2_key_generate()
    dgst = sm2.sm2_public_key_digest(key)
    assert len(dgst) == 32

@test("SM2 ZA 计算")
def test_sm2_compute_z():
    key = sm2.sm2_key_generate()
    z = sm2.sm2_compute_z(key.public_key, sm2.SM2_DEFAULT_ID)
    assert len(z) == 32

@test("SM2 底层签名验签 (do_sign/do_verify)")
def test_sm2_do_sign_verify():
    key = sm2.sm2_key_generate()
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"test message")
    dgst = sm3.sm3_finish(ctx)
    r, s = sm2.sm2_do_sign(key, dgst)
    assert len(r) == 32 and len(s) == 32
    assert sm2.sm2_do_verify(key, dgst, r, s), "验签失败"

@test("SM2 DER 签名验签")
def test_sm2_sign_verify():
    key = sm2.sm2_key_generate()
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"test message for DER")
    dgst = sm3.sm3_finish(ctx)
    sig = sm2.sm2_sign(key, dgst)
    assert len(sig) > 0
    assert sm2.sm2_verify(key, dgst, sig), "DER验签失败"

@test("SM2 流式签名验签")
def test_sm2_streaming_sign():
    key = sm2.sm2_key_generate()
    msg = b"Hello, SM2! This is a test message for signature."
    sign_ctx = sm2.sm2_sign_init(key, sm2.SM2_DEFAULT_ID)
    sm2.sm2_sign_update(sign_ctx, msg[:10])
    sm2.sm2_sign_update(sign_ctx, msg[10:])
    sig = sm2.sm2_sign_finish(sign_ctx)
    verify_ctx = sm2.sm2_verify_init(key, sm2.SM2_DEFAULT_ID)
    sm2.sm2_verify_update(verify_ctx, msg[:10])
    sm2.sm2_verify_update(verify_ctx, msg[10:])
    assert sm2.sm2_verify_finish(verify_ctx, sig), "流式验签失败"

@test("SM2 快速签名")
def test_sm2_fast_sign():
    key = sm2.sm2_key_generate()
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"fast sign test")
    dgst = sm3.sm3_finish(ctx)
    fast_priv = sm2.sm2_fast_sign_compute_key(key)
    pre_comp = sm2.sm2_fast_sign_pre_compute()
    r, s = sm2.sm2_fast_sign(fast_priv, pre_comp, dgst)
    assert len(r) == 32 and len(s) == 32

@test("SM2 固定长度签名")
def test_sm2_fixlen_sign():
    key = sm2.sm2_key_generate()
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"fixlen test")
    dgst = sm3.sm3_finish(ctx)
    sig = sm2.sm2_sign_fixlen(key, dgst, 70)
    assert len(sig) == 70

@test("SM2 底层加密解密 (do_encrypt/do_decrypt)")
def test_sm2_do_encrypt_decrypt():
    key = sm2.sm2_key_generate()
    pt = b"SM2 encryption test"
    ct = sm2.sm2_do_encrypt(key, pt)
    pt2 = sm2.sm2_do_decrypt(key, ct)
    assert pt2 == pt, f"SM2底层解密不匹配: {pt2} != {pt}"

@test("SM2 DER 加密解密")
def test_sm2_encrypt_decrypt():
    key = sm2.sm2_key_generate()
    pt = b"SM2 DER crypto test"
    ct = sm2.sm2_encrypt(key, pt)
    pt2 = sm2.sm2_decrypt(key, ct)
    assert pt2 == pt, f"SM2 DER解密不匹配"

@test("SM2 预计算加密")
def test_sm2_pre_comp_encrypt():
    key = sm2.sm2_key_generate()
    pt = b"PreComp test"
    pre = sm2.sm2_encrypt_pre_compute()
    ct = sm2.sm2_do_encrypt_ex(key, pre, pt)
    pt2 = sm2.sm2_do_decrypt(key, ct)
    assert pt2 == pt

@test("SM2 流式加密解密")
def test_sm2_streaming_encrypt():
    key = sm2.sm2_key_generate()
    pt = b"SM2 streaming encryption test"
    enc_ctx = sm2.sm2_encrypt_init()
    sm2.sm2_encrypt_update(enc_ctx, pt[:5])
    sm2.sm2_encrypt_update(enc_ctx, pt[5:])
    ct = sm2.sm2_encrypt_finish(enc_ctx, key)
    dec_ctx = sm2.sm2_decrypt_init()
    sm2.sm2_decrypt_update(dec_ctx, ct)
    pt2 = sm2.sm2_decrypt_finish(dec_ctx, key)
    assert pt2 == pt, f"SM2流式解密不匹配: {pt2} != {pt}"

@test("SM2 ECDH 密钥交换")
def test_sm2_ecdh():
    keyA = sm2.sm2_key_generate()
    keyB = sm2.sm2_key_generate()
    shared_A = sm2.sm2_do_ecdh(keyA, keyB)
    shared_B = sm2.sm2_do_ecdh(keyB, keyA)
    assert len(shared_A) == 32
    assert shared_A == shared_B, "ECDH密钥不一致"

@test("SM2 ECDH 非压缩点")
def test_sm2_ecdh_uncompressed():
    keyA = sm2.sm2_key_generate()
    keyB = sm2.sm2_key_generate()
    shared_A = sm2.sm2_do_ecdh(keyA, keyB)
    pubB = sm2_z256.sm2_z256_point_to_uncompressed_octets(keyB.public_key)
    shared_A2 = sm2.sm2_ecdh(keyA, pubB)
    assert shared_A == shared_A2, "ECDH非压缩点结果不一致"

@test("SM2 签名上下文重置")
def test_sm2_sign_reset():
    key = sm2.sm2_key_generate()
    ctx = sm2.sm2_sign_init(key)
    sm2.sm2_sign_update(ctx, b"AAA")
    sm2.sm2_sign_reset(ctx)
    sm2.sm2_sign_update(ctx, b"BBB")
    sig = sm2.sm2_sign_finish(ctx)
    vctx = sm2.sm2_verify_init(key)
    sm2.sm2_verify_update(vctx, b"BBB")
    assert sm2.sm2_verify_finish(vctx, sig), "重置后签名验签失败"

@test("SM2 加密上下文重置")
def test_sm2_encrypt_reset():
    key = sm2.sm2_key_generate()
    ctx = sm2.sm2_encrypt_init()
    sm2.sm2_encrypt_update(ctx, b"data1")
    sm2.sm2_encrypt_reset(ctx)
    sm2.sm2_encrypt_update(ctx, b"data2")
    ct = sm2.sm2_encrypt_finish(ctx, key)
    dctx = sm2.sm2_decrypt_init()
    sm2.sm2_decrypt_update(dctx, ct)
    pt = sm2.sm2_decrypt_finish(dctx, key)
    assert pt == b"data2", f"重置后加密解密不匹配: {pt}"

@test("SM2 错误签名拒绝")
def test_sm2_wrong_signature():
    key = sm2.sm2_key_generate()
    ctx = sm3.sm3_init()
    sm3.sm3_update(ctx, b"real message")
    dgst = sm3.sm3_finish(ctx)
    sig = sm2.sm2_sign(key, dgst)
    # 用错误摘要验签
    ctx2 = sm3.sm3_init()
    sm3.sm3_update(ctx2, b"wrong message")
    dgst2 = sm3.sm3_finish(ctx2)
    # 用错误摘要验签应该失败
    result = sm2.sm2_verify(key, dgst2, sig)
    assert not result, "错误摘要不应该验签成功"

@test("SM2 明文长度校验")
def test_sm2_plaintext_limit():
    key = sm2.sm2_key_generate()
    try:
        # 超过256字节应该报错
        sm2.sm2_do_encrypt(key, b"A" * 260)
        assert False, "应该拒绝超长明文"
    except (ValueError, NativeError):
        pass

@test("SM2 摘要长度校验")
def test_sm2_digest_len():
    key = sm2.sm2_key_generate()
    try:
        sm2.sm2_do_sign(key, b"short")
        assert False, "应该拒绝非32字节摘要"
    except ValueError:
        pass


# ============================================================
# SM2 Z256 低层数学
# ============================================================
@test("SM2 Z256 基本运算")
def test_sm2_z256_basic():
    a = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
    b = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000002")
    c = sm2_z256.sm2_z256_modp_add(a, b)
    assert sm2_z256.sm2_z256_equ_hex(c, "0000000000000000000000000000000000000000000000000000000000000003")

@test("SM2 Z256 乘法和减法")
def test_sm2_z256_mul_sub():
    a = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000005")
    b = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    c = sm2_z256.sm2_z256_modp_sub(a, b)
    assert sm2_z256.sm2_z256_equ_hex(c, "0000000000000000000000000000000000000000000000000000000000000002")

@test("SM2 Z256 字节转换")
def test_sm2_z256_bytes():
    data = bytes(32)
    a = sm2_z256.sm2_z256_from_bytes(data)
    assert sm2_z256.sm2_z256_is_zero(a)
    b = sm2_z256.sm2_z256_to_bytes(a)
    assert b == data

@test("SM2 Z256 比较")
def test_sm2_z256_cmp():
    a = sm2_z256.sm2_z256_set_one()
    b = sm2_z256.sm2_z256_set_zero()
    assert not sm2_z256.sm2_z256_equ(a, b)
    assert sm2_z256.sm2_z256_is_zero(b)
    assert not sm2_z256.sm2_z256_is_zero(a)

@test("SM2 Z256 曲线参数")
def test_sm2_z256_params():
    p = sm2_z256.sm2_z256_prime()
    n = sm2_z256.sm2_z256_order()
    assert p is not None
    assert n is not None

@test("SM2 Z256 点运算")
def test_sm2_z256_points():
    # 生成元
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    assert sm2_z256.sm2_z256_point_is_on_curve(gen)

@test("SM2 Z256 无穷远点")
def test_sm2_z256_infinity():
    inf = sm2_z256.sm2_z256_point_set_infinity()
    assert sm2_z256.sm2_z256_point_is_at_infinity(inf)

@test("SM2 Z256 点编码")
def test_sm2_z256_point_encoding():
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    uncomp = sm2_z256.sm2_z256_point_to_uncompressed_octets(gen)
    assert len(uncomp) == 65 and uncomp[0] == 0x04
    comp = sm2_z256.sm2_z256_point_to_compressed_octets(gen)
    assert len(comp) == 33

@test("SM2 Z256 点从字节构造")
def test_sm2_z256_point_from_bytes():
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    octets = sm2_z256.sm2_z256_point_to_uncompressed_octets(gen)
    P = sm2_z256.sm2_z256_point_from_octets(octets)
    assert sm2_z256.sm2_z256_point_is_on_curve(P)

@test("SM2 Z256 标量乘预计算")
def test_sm2_z256_mul_pre_compute():
    k = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    pre = sm2_z256.sm2_z256_point_mul_pre_compute(gen)
    R1 = sm2_z256.sm2_z256_point_mul(k, gen)
    R2 = sm2_z256.sm2_z256_point_mul_ex(k, pre)
    assert sm2_z256.sm2_z256_point_equ(R1, R2)

@test("SM2 Z256 点加法")
def test_sm2_z256_point_add():
    k1 = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
    k2 = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000002")
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    P1 = sm2_z256.sm2_z256_point_mul(k1, gen)
    P2 = sm2_z256.sm2_z256_point_mul(k2, gen)
    P3 = sm2_z256.sm2_z256_point_add(P1, P2)
    k3 = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    P3_expected = sm2_z256.sm2_z256_point_mul(k3, gen)
    assert sm2_z256.sm2_z256_point_equ(P3, P3_expected)

@test("SM2 Z256 点取负和减法")
def test_sm2_z256_point_neg():
    k = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000005")
    gen = sm2_z256.sm2_z256_point_mul_generator(
        sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"))
    P = sm2_z256.sm2_z256_point_mul(k, gen)
    negP = sm2_z256.sm2_z256_point_neg(P)
    sumP = sm2_z256.sm2_z256_point_add(P, negP)
    assert sm2_z256.sm2_z256_point_is_at_infinity(sumP)

@test("SM2 Z256 随机数")
def test_sm2_z256_rand():
    n = sm2_z256.sm2_z256_order()
    r = sm2_z256.sm2_z256_rand_range(n)
    assert r is not None

@test("SM2 Z256 模逆运算")
def test_sm2_z256_mod_inv():
    a = sm2_z256.sm2_z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    inv_a = sm2_z256.sm2_z256_modn_inv(a)
    one = sm2_z256.sm2_z256_modn_mul(a, inv_a)
    assert sm2_z256.sm2_z256_equ_hex(one, "0000000000000000000000000000000000000000000000000000000000000001")


# ============================================================
# SM9 标识密码
# ============================================================
@test("SM9 签名主密钥生成")
def test_sm9_sign_master_key_gen():
    master = sm9.sm9_sign_master_key_generate()
    assert master is not None

@test("SM9 签名密钥提取")
def test_sm9_sign_key_extract():
    master = sm9.sm9_sign_master_key_generate()
    key = sm9.sm9_sign_master_key_extract_key(master, "alice@test.com")
    assert key is not None

@test("SM9 流式签名验签")
def test_sm9_sign_verify():
    master = sm9.sm9_sign_master_key_generate()
    key = sm9.sm9_sign_master_key_extract_key(master, "alice@test.com")
    ctx = sm9.sm9_sign_init()
    sm9.sm9_sign_update(ctx, b"Hello, SM9!")
    sig = sm9.sm9_sign_finish(ctx, key)
    assert len(sig) > 0
    vctx = sm9.sm9_verify_init()
    sm9.sm9_verify_update(vctx, b"Hello, SM9!")
    assert sm9.sm9_verify_finish(vctx, sig, master, "alice@test.com"), "验签失败"

@test("SM9 流式签名验签（中文标识）")
def test_sm9_sign_verify_cn():
    master = sm9.sm9_sign_master_key_generate()
    key = sm9.sm9_sign_master_key_extract_key(master, "张三@test.com")
    ctx = sm9.sm9_sign_init()
    sm9.sm9_sign_update(ctx, b"SM9 test with Chinese ID")
    sig = sm9.sm9_sign_finish(ctx, key)
    vctx = sm9.sm9_verify_init()
    sm9.sm9_verify_update(vctx, b"SM9 test with Chinese ID")
    assert sm9.sm9_verify_finish(vctx, sig, master, "张三@test.com"), "中文标识验签失败"

@test("SM9 底层签名验签 (do_sign/do_verify)")
def test_sm9_do_sign_verify():
    master = sm9.sm9_sign_master_key_generate()
    key = sm9.sm9_sign_master_key_extract_key(master, "bob@test.com")
    sm3_ctx = sm3.sm3_init()
    sm3.sm3_update(sm3_ctx, b"message for do_sign")
    sig = sm9.sm9_do_sign(key, sm3_ctx)
    sm3_ctx2 = sm3.sm3_init()
    sm3.sm3_update(sm3_ctx2, b"message for do_sign")
    assert sm9.sm9_do_verify(master, "bob@test.com", sm3_ctx2, sig), "底层验签失败"

@test("SM9 加密主密钥生成")
def test_sm9_enc_master_key_gen():
    master = sm9.sm9_enc_master_key_generate()
    assert master is not None

@test("SM9 加密密钥提取")
def test_sm9_enc_key_extract():
    master = sm9.sm9_enc_master_key_generate()
    key = sm9.sm9_enc_master_key_extract_key(master, "alice@test.com")
    assert key is not None

@test("SM9 加密解密")
def test_sm9_encrypt_decrypt():
    master = sm9.sm9_enc_master_key_generate()
    key = sm9.sm9_enc_master_key_extract_key(master, "alice@test.com")
    pt = b"SM9 encryption test"
    ct = sm9.sm9_encrypt(master, "alice@test.com", pt)
    pt2 = sm9.sm9_decrypt(key, "alice@test.com", ct)
    assert pt2 == pt, f"SM9解密不匹配: {pt2}"

@test("SM9 底层加密解密 (do_encrypt/do_decrypt)")
def test_sm9_do_encrypt_decrypt():
    master = sm9.sm9_enc_master_key_generate()
    key = sm9.sm9_enc_master_key_extract_key(master, "bob@test.com")
    pt = b"SM9 do_encrypt test"
    C1, c2, c3 = sm9.sm9_do_encrypt(master, "bob@test.com", pt)
    pt2 = sm9.sm9_do_decrypt(key, "bob@test.com", C1, c2, c3)
    assert pt2 == pt

@test("SM9 KEM 密钥封装")
def test_sm9_kem():
    master = sm9.sm9_enc_master_key_generate()
    key = sm9.sm9_enc_master_key_extract_key(master, "alice@test.com")
    kbuf, C = sm9.sm9_kem_encrypt(master, "alice@test.com", 32)
    kbuf2 = sm9.sm9_kem_decrypt(key, "alice@test.com", C, 32)
    assert kbuf == kbuf2, "KEM密钥不一致"

@test("SM9 KEM 不同长度")
def test_sm9_kem_len():
    master = sm9.sm9_enc_master_key_generate()
    key = sm9.sm9_enc_master_key_extract_key(master, "test@test.com")
    kbuf, C = sm9.sm9_kem_encrypt(master, "test@test.com", 16)
    kbuf2 = sm9.sm9_kem_decrypt(key, "test@test.com", C, 16)
    assert kbuf == kbuf2

@test("SM9 密钥交换")
def test_sm9_exchange():
    master = sm9.sm9_exch_master_key_generate()
    keyA = sm9.sm9_exch_master_key_extract_key(master, "alice@test.com")
    keyB = sm9.sm9_exch_master_key_extract_key(master, "bob@test.com")
    RA, rA = sm9.sm9_exch_step_1A(master, "bob@test.com")
    RB, skB = sm9.sm9_exch_step_1B(master, "alice@test.com", "bob@test.com", keyB, RA)
    skA = sm9.sm9_exch_step_2A(master, "alice@test.com", "bob@test.com", keyA, rA, RA, RB)
    assert skA == skB, "密钥交换不一致"

@test("SM9 错误标识验签失败")
def test_sm9_wrong_id_verify():
    master = sm9.sm9_sign_master_key_generate()
    key = sm9.sm9_sign_master_key_extract_key(master, "alice@test.com")
    ctx = sm9.sm9_sign_init()
    sm9.sm9_sign_update(ctx, b"test")
    sig = sm9.sm9_sign_finish(ctx, key)
    vctx = sm9.sm9_verify_init()
    sm9.sm9_verify_update(vctx, b"test")
    # 用错误的标识验签
    result = sm9.sm9_verify_finish(vctx, sig, master, "bob@test.com")
    assert not result, "错误标识不应该验签成功"

@test("SM9 z256_hash1")
def test_sm9_hash1():
    h1 = sm9.sm9_z256_hash1("alice@test.com", sm9.SM9_HID_SIGN)
    assert h1 is not None

@test("SM9 OID")
def test_sm9_oid():
    name = sm9.sm9_oid_name(0)
    # OID 0 可能不存在，返回None也是正常的
    assert name is None or (isinstance(name, str) and len(name) > 0)


# ============================================================
# SM9 Z256 低层数学
# ============================================================
@test("SM9 Z256 基本运算")
def test_sm9_z256_basic():
    a = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
    b = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000002")
    c = sm9_z256.z256_modp_add(a, b)
    assert sm9_z256.z256_equ_hex(c, "0000000000000000000000000000000000000000000000000000000000000003")

@test("SM9 Z256 字节转换")
def test_sm9_z256_bytes():
    a = sm9_z256.z256_set_zero()
    assert sm9_z256.z256_is_zero(a)
    b = sm9_z256.z256_to_bytes(a)
    assert b == bytes(32)

@test("SM9 Z256 十六进制")
def test_sm9_z256_hex():
    a = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000001")
    h = sm9_z256.z256_to_hex(a)
    assert len(h) == 64

@test("SM9 Z256 比较")
def test_sm9_z256_cmp():
    a = sm9_z256.z256_set_one()
    b = sm9_z256.z256_set_zero()
    assert sm9_z256.z256_cmp(a, b) > 0
    assert sm9_z256.z256_cmp(b, a) < 0

@test("SM9 Z256 模运算")
def test_sm9_z256_mod():
    a = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000005")
    b = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    c = sm9_z256.z256_modn_sub(a, b)
    assert sm9_z256.z256_equ_hex(c, "0000000000000000000000000000000000000000000000000000000000000002")

@test("SM9 Fp2 运算")
def test_sm9_fp2():
    a = sm9_z256.fp2_set_one()
    assert sm9_z256.fp2_is_one(a)
    b = sm9_z256.fp2_rand()
    c = sm9_z256.fp2_add(a, b)
    assert not sm9_z256.fp2_equ(c, b)

@test("SM9 Fp4 运算")
def test_sm9_fp4():
    a = sm9_z256.fp4_rand()
    b = sm9_z256.fp4_rand()
    c = sm9_z256.fp4_add(a, b)
    assert not sm9_z256.fp4_is_zero(c) or (sm9_z256.fp4_is_zero(a) and sm9_z256.fp4_is_zero(b))

@test("SM9 Fp12 运算")
def test_sm9_fp12():
    one = sm9_z256.fp12_set_one()
    a = sm9_z256.fp12_rand()
    b = sm9_z256.fp12_mul(a, one)
    assert sm9_z256.fp12_equ(a, b)

@test("SM9 G1 生成元")
def test_sm9_g1_generator():
    P1 = sm9_z256.z256_generator()
    assert sm9_z256.z256_point_is_on_curve(P1)

@test("SM9 G2 生成元")
def test_sm9_g2_generator():
    P2 = sm9_z256.z256_twist_generator()
    assert sm9_z256.z256_twist_point_is_on_curve(P2)

@test("SM9 G1 点运算")
def test_sm9_g1_ops():
    P1 = sm9_z256.z256_generator()
    P2 = sm9_z256.z256_point_dbl(P1)
    assert sm9_z256.z256_point_is_on_curve(P2)
    P3 = sm9_z256.z256_point_add(P1, P2)
    assert sm9_z256.z256_point_is_on_curve(P3)

@test("SM9 G2 点运算")
def test_sm9_g2_ops():
    P2 = sm9_z256.z256_twist_generator()
    Q = sm9_z256.z256_twist_point_dbl(P2)
    assert sm9_z256.z256_twist_point_is_on_curve(Q)

@test("SM9 G1 标量乘")
def test_sm9_g1_scalar_mul():
    k = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    P1 = sm9_z256.z256_generator()
    R = sm9_z256.z256_point_mul(k, P1)
    assert sm9_z256.z256_point_is_on_curve(R)

@test("SM9 G2 标量乘")
def test_sm9_g2_scalar_mul():
    k = sm9_z256.z256_from_hex("0000000000000000000000000000000000000000000000000000000000000003")
    P2 = sm9_z256.z256_twist_generator()
    R = sm9_z256.z256_twist_point_mul(k, P2)
    assert sm9_z256.z256_twist_point_is_on_curve(R)

@test("SM9 配对运算")
def test_sm9_pairing():
    P1 = sm9_z256.z256_generator()
    P2 = sm9_z256.z256_twist_generator()
    pairing = sm9_z256.z256_pairing(P2, P1)
    assert pairing is not None

@test("SM9 G1 点编码")
def test_sm9_g1_encoding():
    P1 = sm9_z256.z256_generator()
    octets = sm9_z256.z256_point_to_uncompressed_octets(P1)
    assert len(octets) == 65 and octets[0] == 0x04
    Q = sm9_z256.z256_point_from_uncompressed_octets(octets)
    assert sm9_z256.z256_point_equ(P1, Q)

@test("SM9 G2 点编码")
def test_sm9_g2_encoding():
    P2 = sm9_z256.z256_twist_generator()
    octets = sm9_z256.z256_twist_point_to_uncompressed_octets(P2)
    assert len(octets) == 129 and octets[0] == 0x04

@test("SM9 最终求幂")
def test_sm9_final_exponent():
    P1 = sm9_z256.z256_generator()
    P2 = sm9_z256.z256_twist_generator()
    f = sm9_z256.z256_pairing(P2, P1)
    r = sm9_z256.z256_final_exponent(f)
    assert r is not None

@test("SM9 Fp12 序列化")
def test_sm9_fp12_serialize():
    a = sm9_z256.fp12_rand()
    data = sm9_z256.fp12_to_bytes(a)
    assert len(data) == 384
    b = sm9_z256.fp12_from_bytes(data)
    assert sm9_z256.fp12_equ(a, b)


# ============================================================
# ZUC 祖冲之序列密码
# ============================================================
@test("ZUC-128 基本加密解密")
def test_zuc_basic():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    state = zuc.ZUC_STATE()
    zuc.zuc_init(state, key, iv)
    pt = b"Hello, ZUC-128! This is a test message for ZUC stream cipher."
    ct = zuc.zuc_encrypt(state, pt)
    state2 = zuc.ZUC_STATE()
    zuc.zuc_init(state2, key, iv)
    pt2 = zuc.zuc_encrypt(state2, ct)
    assert pt2 == pt, f"ZUC解密不匹配"

@test("ZUC-128 密钥流生成")
def test_zuc_keystream():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    state = zuc.ZUC_STATE()
    zuc.zuc_init(state, key, iv)
    ks = zuc.zuc_generate_keystream(state, 10)
    assert len(ks) == 40  # 10 words * 4 bytes

@test("ZUC-128 单个密钥字")
def test_zuc_keyword():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    state = zuc.ZUC_STATE()
    zuc.zuc_init(state, key, iv)
    kw = zuc.zuc_generate_keyword(state)
    assert isinstance(kw, int)

@test("ZUC-128 流式加密")
def test_zuc_streaming():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    pt = b"ZUC streaming test message!"
    zuc_ctx = zuc.Zuc(key, iv)
    ct1 = zuc_ctx.update(pt[:10])
    ct2 = zuc_ctx.update(pt[10:])
    ct3 = zuc_ctx.finish()
    ct = ct1 + ct2 + ct3
    zuc_ctx2 = zuc.Zuc(key, iv)
    pt1 = zuc_ctx2.update(ct)
    pt2 = zuc_ctx2.finish()
    assert pt1 + pt2 == pt, "ZUC流式解密不匹配"

@test("ZUC-128 MAC")
def test_zuc_mac():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    msg = b"Message for MAC"
    ctx = zuc.ZUC_MAC_CTX()
    zuc.zuc_mac_init(ctx, key, iv)
    zuc.zuc_mac_update(ctx, msg)
    mac = zuc.zuc_mac_finish(ctx, msg, len(msg) * 8)
    assert len(mac) == 4

@test("ZUC-128 MAC 便捷类")
def test_zuc_mac_class():
    key = rand_bytes(16)
    iv = rand_bytes(16)
    msg = b"Test MAC"
    obj = zuc.ZucMac(key, iv)
    obj.update(msg)
    mac = obj.finish(msg, len(msg) * 8)
    assert len(mac) == 4

@test("ZUC-128 EEA 加密")
def test_zuc_eea():
    key = rand_bytes(16)
    input_words = [0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF]
    nbits = len(input_words) * 32
    output = zuc.zuc_eea_encrypt(input_words, nbits, key, 0x12345678, 5, 0)
    recovered = zuc.zuc_eea_encrypt(output, nbits, key, 0x12345678, 5, 0)
    assert recovered == input_words, "EEA解密不匹配"

@test("ZUC-128 EIA 完整性")
def test_zuc_eia():
    key = rand_bytes(16)
    data = [0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF]
    nbits = len(data) * 32
    mac = zuc.zuc_eia_generate_mac(data, nbits, key, 0x12345678, 5, 0)
    assert isinstance(mac, int)

@test("ZUC-256 密钥流生成")
def test_zuc256_keystream():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    state = zuc.ZUC_STATE()
    zuc.zuc256_init(state, key, iv)
    ks = zuc.zuc256_generate_keystream(state, 8)
    assert len(ks) == 32

@test("ZUC-256 单个密钥字")
def test_zuc256_keyword():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    state = zuc.ZUC_STATE()
    zuc.zuc256_init(state, key, iv)
    kw = zuc.zuc256_generate_keyword(state)
    assert isinstance(kw, int)

@test("ZUC-256 MAC 32位")
def test_zuc256_mac32():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    msg = b"ZUC-256 MAC test"
    ctx = zuc.ZUC256_MAC_CTX()
    zuc.zuc256_mac_init(ctx, key, iv, 32)
    zuc.zuc256_mac_update(ctx, msg)
    mac = zuc.zuc256_mac_finish(ctx, msg, len(msg) * 8, 4)
    assert len(mac) == 4

@test("ZUC-256 MAC 64位")
def test_zuc256_mac64():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    msg = b"ZUC-256 MAC test"
    ctx = zuc.ZUC256_MAC_CTX()
    zuc.zuc256_mac_init(ctx, key, iv, 64)
    zuc.zuc256_mac_update(ctx, msg)
    mac = zuc.zuc256_mac_finish(ctx, msg, len(msg) * 8, 8)
    assert len(mac) == 8

@test("ZUC-256 MAC 128位")
def test_zuc256_mac128():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    msg = b"ZUC-256 MAC test"
    ctx = zuc.ZUC256_MAC_CTX()
    zuc.zuc256_mac_init(ctx, key, iv, 128)
    zuc.zuc256_mac_update(ctx, msg)
    mac = zuc.zuc256_mac_finish(ctx, msg, len(msg) * 8, 16)
    assert len(mac) == 16

@test("ZUC-256 MAC 便捷类")
def test_zuc256_mac_class():
    key = rand_bytes(32)
    iv = rand_bytes(23)
    msg = b"ZUC-256 MAC class test"
    obj = zuc.Zuc256Mac(key, iv, 128)
    obj.update(msg)
    mac = obj.finish(msg, len(msg) * 8)
    assert len(mac) == 16

@test("ZUC 密钥长度校验")
def test_zuc_key_len():
    state = zuc.ZUC_STATE()
    try:
        zuc.zuc_init(state, b"short", bytes(16))
        assert False, "应拒绝短密钥"
    except ValueError:
        pass

@test("ZUC IV长度校验")
def test_zuc_iv_len():
    state = zuc.ZUC_STATE()
    try:
        zuc.zuc_init(state, bytes(16), b"short")
        assert False, "应拒绝短IV"
    except ValueError:
        pass


# ============================================================
# 主函数
# ============================================================
def main():
    global PASS_COUNT, FAIL_COUNT, SKIP_COUNT

    print("=" * 70)
    print("GmLLC 库全面功能测试")
    print("=" * 70)
    sys.stdout.flush()

    # 基础信息
    print("\n[基础信息]")
    test_version()
    test_rand_bytes()

    # SM3
    print("\n[SM3 密码杂凑算法]")
    test_sm3_basic()
    test_sm3_empty()
    test_sm3_streaming()
    test_sm3_class()
    test_sm3_reset()
    test_sm3_copy()
    test_sm3_hmac()
    test_sm3_hmac_diff_key()
    test_sm3_hmac_class()
    test_sm3_kdf()
    test_sm3_kdf_len()
    test_sm3_pbkdf2()
    test_sm3_pbkdf2_deterministic()
    test_sm3_digest()
    test_sm3_compress_blocks()

    # SM4
    print("\n[SM4 分组密码]")
    test_sm4_basic()
    test_sm4_ecb_blocks()
    test_sm4_cbc_padding()
    test_sm4_cbc_blocks()
    test_sm4_cbc_streaming()
    test_sm4_ctr()
    test_sm4_ctr_blocks()
    test_sm4_ctr32()
    test_sm4_gcm()
    test_sm4_gcm_wrong_tag()
    test_sm4_gcm_streaming()
    test_sm4_ecb_class()
    test_sm4_key_len()

    # SM2
    print("\n[SM2 椭圆曲线公钥密码]")
    test_sm2_keygen()
    test_sm2_set_private()
    test_sm2_pubkey_digest()
    test_sm2_compute_z()
    test_sm2_do_sign_verify()
    test_sm2_sign_verify()
    test_sm2_streaming_sign()
    test_sm2_fast_sign()
    test_sm2_fixlen_sign()
    test_sm2_do_encrypt_decrypt()
    test_sm2_encrypt_decrypt()
    test_sm2_pre_comp_encrypt()
    test_sm2_streaming_encrypt()
    test_sm2_ecdh()
    test_sm2_ecdh_uncompressed()
    test_sm2_sign_reset()
    test_sm2_encrypt_reset()
    test_sm2_wrong_signature()
    test_sm2_plaintext_limit()
    test_sm2_digest_len()

    # SM2 Z256
    print("\n[SM2 Z256 低层数学]")
    test_sm2_z256_basic()
    test_sm2_z256_mul_sub()
    test_sm2_z256_bytes()
    test_sm2_z256_cmp()
    test_sm2_z256_params()
    test_sm2_z256_points()
    test_sm2_z256_infinity()
    test_sm2_z256_point_encoding()
    test_sm2_z256_point_from_bytes()
    test_sm2_z256_mul_pre_compute()
    test_sm2_z256_point_add()
    test_sm2_z256_point_neg()
    test_sm2_z256_rand()
    test_sm2_z256_mod_inv()

    # SM9
    print("\n[SM9 标识密码]")
    test_sm9_sign_master_key_gen()
    test_sm9_sign_key_extract()
    test_sm9_sign_verify()
    test_sm9_sign_verify_cn()
    test_sm9_do_sign_verify()
    test_sm9_enc_master_key_gen()
    test_sm9_enc_key_extract()
    test_sm9_encrypt_decrypt()
    test_sm9_do_encrypt_decrypt()
    test_sm9_kem()
    test_sm9_kem_len()
    test_sm9_exchange()
    test_sm9_wrong_id_verify()
    test_sm9_hash1()
    test_sm9_oid()

    # SM9 Z256
    print("\n[SM9 Z256 低层数学]")
    test_sm9_z256_basic()
    test_sm9_z256_bytes()
    test_sm9_z256_hex()
    test_sm9_z256_cmp()
    test_sm9_z256_mod()
    test_sm9_fp2()
    test_sm9_fp4()
    test_sm9_fp12()
    test_sm9_g1_generator()
    test_sm9_g2_generator()
    test_sm9_g1_ops()
    test_sm9_g2_ops()
    test_sm9_g1_scalar_mul()
    test_sm9_g2_scalar_mul()
    test_sm9_pairing()
    test_sm9_g1_encoding()
    test_sm9_g2_encoding()
    test_sm9_final_exponent()
    test_sm9_fp12_serialize()

    # ZUC
    print("\n[ZUC 祖冲之序列密码]")
    test_zuc_basic()
    test_zuc_keystream()
    test_zuc_keyword()
    test_zuc_streaming()
    test_zuc_mac()
    test_zuc_mac_class()
    test_zuc_eea()
    test_zuc_eia()
    test_zuc256_keystream()
    test_zuc256_keyword()
    test_zuc256_mac32()
    test_zuc256_mac64()
    test_zuc256_mac128()
    test_zuc256_mac_class()
    test_zuc_key_len()
    test_zuc_iv_len()

    # 结果汇总
    print("\n" + "=" * 70)
    total = PASS_COUNT + FAIL_COUNT + SKIP_COUNT
    print(f"测试结果: {total} 项测试")
    print(f"  通过: {PASS_COUNT}")
    print(f"  失败: {FAIL_COUNT}")
    if FAIL_DETAILS:
        print(f"\n失败详情:")
        for i, detail in enumerate(FAIL_DETAILS, 1):
            print(f"\n--- 失败 #{i} ---")
            print(detail)
    print("=" * 70)

    return FAIL_COUNT == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)