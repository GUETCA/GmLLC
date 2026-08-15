# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm2.py - SM2 椭圆曲线公钥密码接口
# 封装 sm2.h 中定义的所有SM2函数
# 包括: 密钥生成、签名/验签、加密/解密、ECDH密钥交换

from ctypes import *
from . import gmssl, libc, _check
from .sm2_z256 import SM2_Z256_POINT, SM2_Z256_AFFINE_POINT
from .error import NativeError, StateError

# === SM3 CTX ===
SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64
SM3_STATE_WORDS = 8

class SM3_CTX(Structure):
    _fields_ = [
        ("digest", c_uint32 * SM3_STATE_WORDS),
        ("nblocks", c_uint64),
        ("block", c_uint8 * SM3_BLOCK_SIZE),
        ("num", c_size_t),
    ]

# === 常量 ===
SM2_DEFAULT_ID = "1234567812345678"
SM2_DEFAULT_ID_LENGTH = 16
SM2_MAX_ID_BITS = 65535
SM2_MAX_ID_LENGTH = 8192
SM2_MAX_SIGNATURE_SIZE = 72
SM2_MIN_SIGNATURE_SIZE = 8
SM2_MIN_PLAINTEXT_SIZE = 1
SM2_MAX_PLAINTEXT_SIZE = 255
SM2_MIN_CIPHERTEXT_SIZE = 45
SM2_MAX_CIPHERTEXT_SIZE = 366
SM2_PUBLIC_KEY_SIZE = 64
SM2_PRIVATE_KEY_SIZE = 96
SM2_PRIVATE_KEY_DEFAULT_SIZE = 120
SM2_PRIVATE_KEY_BUF_SIZE = 512
SM2_SIGN_PRE_COMP_COUNT = 32
SM2_ENC_PRE_COMP_NUM = 8

# === 密钥结构 ===

class SM2_KEY(Structure):
    _fields_ = [
        ("public_key", SM2_Z256_POINT),
        ("private_key", c_uint64 * 4),
    ]

class SM2_SIGNATURE(Structure):
    _fields_ = [
        ("r", c_uint8 * 32),
        ("s", c_uint8 * 32),
    ]

class SM2_SIGN_PRE_COMP(Structure):
    _fields_ = [
        ("k", c_uint64 * 4),
        ("x1_modn", c_uint64 * 4),
    ]

class SM2_POINT(Structure):
    _fields_ = [
        ("x", c_uint8 * 32),
        ("y", c_uint8 * 32),
    ]

class SM2_CIPHERTEXT(Structure):
    _fields_ = [
        ("point", SM2_POINT),
        ("hash", c_uint8 * 32),
        ("ciphertext_size", c_uint8),
        ("ciphertext", c_uint8 * SM2_MAX_PLAINTEXT_SIZE),
    ]

class SM2_ENC_PRE_COMP(Structure):
    _fields_ = [
        ("k", c_uint64 * 4),
        ("C1", SM2_POINT),
    ]

# === 密钥管理 ===

def sm2_key_generate():
    """生成SM2密钥对"""
    key = SM2_KEY()
    ret = gmssl.sm2_key_generate(byref(key))
    _check(ret, "sm2_key_generate失败")
    return key

def sm2_key_set_private_key(key, private_key):
    """设置SM2私钥"""
    ret = gmssl.sm2_key_set_private_key(byref(key), private_key)
    _check(ret, "sm2_key_set_private_key失败")

def sm2_key_set_public_key(key, public_key):
    """设置SM2公钥"""
    ret = gmssl.sm2_key_set_public_key(byref(key), byref(public_key))
    _check(ret, "sm2_key_set_public_key失败")

def sm2_public_key_equ(key1, key2):
    """判断两公钥是否相等"""
    return gmssl.sm2_public_key_equ(byref(key1), byref(key2))

def sm2_public_key_digest(key):
    """计算公钥的SM3摘要"""
    dgst = (c_uint8 * 32)()
    ret = gmssl.sm2_public_key_digest(byref(key), dgst)
    _check(ret, "sm2_public_key_digest失败")
    return bytes(dgst)

def sm2_public_key_from_der(key, data):
    """从 DER 解码公钥"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_public_key_from_der(byref(key), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_public_key_from_der失败")

def sm2_private_key_from_der(key, data):
    """从 DER 解码私钥"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_private_key_from_der(byref(key), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_private_key_from_der失败")

def sm2_public_key_info_from_der(key, data):
    """从 DER 解码公钥信息"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_public_key_info_from_der(byref(key), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_public_key_info_from_der失败")

def sm2_private_key_info_from_der(key, data):
    """从 DER 解码私钥信息"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    attrs = c_void_p()
    attrslen = c_size_t()
    ret = gmssl.sm2_private_key_info_from_der(byref(key), byref(attrs), byref(attrslen), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_private_key_info_from_der失败")

def sm2_private_key_info_decrypt_from_der(key, passwd, data):
    """从 DER 解密私钥信息"""
    attrs = c_void_p()
    attrslen = c_size_t()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_private_key_info_decrypt_from_der(byref(key), byref(attrs), byref(attrslen), passwd.encode('utf-8'), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_private_key_info_decrypt_from_der失败")

# === 签名/验签 ===

def sm2_do_sign(key, dgst):
    """SM2底层签名: 返回(r, s)"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = SM2_SIGNATURE()
    ret = gmssl.sm2_do_sign(byref(key), (c_uint8 * 32)(*dgst), byref(sig))
    _check(ret, "sm2_do_sign失败")
    return bytes(sig.r), bytes(sig.s)

def sm2_do_verify(key, dgst, sig_r, sig_s):
    """SM2底层验签"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = SM2_SIGNATURE()
    sig.r = (c_uint8 * 32)(*sig_r)
    sig.s = (c_uint8 * 32)(*sig_s)
    return gmssl.sm2_do_verify(byref(key), (c_uint8 * 32)(*dgst), byref(sig)) == 1

def sm2_compute_z(pub_key, signer_id=SM2_DEFAULT_ID):
    """计算SM2签名中的ZA值"""
    if isinstance(signer_id, str):
        signer_id = signer_id.encode('utf-8')
    z = create_string_buffer(32)
    gmssl.sm2_compute_z(z, byref(pub_key), c_char_p(signer_id), c_size_t(len(signer_id)))
    return z.raw

def sm2_signature_from_der(data):
    """从 DER 解码签名"""
    sig = SM2_SIGNATURE()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_signature_from_der(byref(sig), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_signature_from_der失败")
    return bytes(sig.r), bytes(sig.s)

def sm2_sign(key, dgst):
    """SM2签名: 返回DER编码签名"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
    siglen = c_size_t()
    ret = gmssl.sm2_sign(byref(key), (c_uint8 * 32)(*dgst), sig, byref(siglen))
    _check(ret, "sm2_sign失败")
    return sig[:siglen.value]

def sm2_verify(key, dgst, sig):
    """SM2验签"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    return gmssl.sm2_verify(byref(key), (c_uint8 * 32)(*dgst), sig, c_size_t(len(sig))) == 1

def sm2_sign_fixlen(key, dgst, siglen):
    """SM2固定长度签名"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = create_string_buffer(siglen)
    ret = gmssl.sm2_sign_fixlen(byref(key), (c_uint8 * 32)(*dgst), c_size_t(siglen), sig)
    _check(ret, "sm2_sign_fixlen失败")
    return sig.raw

# -- 快速签名 --
def sm2_fast_sign_compute_key(key):
    """计算快速签名所需的私钥变换"""
    fast_private = (c_uint64 * 4)()
    ret = gmssl.sm2_fast_sign_compute_key(byref(key), fast_private)
    _check(ret, "sm2_fast_sign_compute_key失败")
    return fast_private

def sm2_fast_sign_pre_compute():
    """预计算快速签名参数"""
    pre_comp = (SM2_SIGN_PRE_COMP * SM2_SIGN_PRE_COMP_COUNT)()
    ret = gmssl.sm2_fast_sign_pre_compute(pre_comp)
    _check(ret, "sm2_fast_sign_pre_compute失败")
    return pre_comp

def sm2_fast_sign(fast_private, pre_comp, dgst):
    """快速签名"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = SM2_SIGNATURE()
    ret = gmssl.sm2_fast_sign(fast_private, pre_comp, (c_uint8 * 32)(*dgst), byref(sig))
    _check(ret, "sm2_fast_sign失败")
    return bytes(sig.r), bytes(sig.s)

def sm2_fast_verify(point_table, dgst, sig_r, sig_s):
    """快速验签"""
    if len(dgst) != 32:
        raise ValueError(f"摘要必须为32字节")
    sig = SM2_SIGNATURE()
    sig.r = (c_uint8 * 32)(*sig_r)
    sig.s = (c_uint8 * 32)(*sig_s)
    return gmssl.sm2_fast_verify(point_table, (c_uint8 * 32)(*dgst), byref(sig)) == 1

# -- 流式签名/验签 --
class SM2_SIGN_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
        ("saved_sm3_ctx", SM3_CTX),
        ("key", SM2_KEY),
        ("fast_sign_private", c_uint64 * 4),
        ("pre_comp", SM2_SIGN_PRE_COMP * SM2_SIGN_PRE_COMP_COUNT),
        ("num_pre_comp", c_uint),
        ("public_point_table", SM2_Z256_POINT * 16),
    ]

class SM2_VERIFY_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
        ("saved_sm3_ctx", SM3_CTX),
        ("key", SM2_KEY),
        ("public_point_table", SM2_Z256_POINT * 16),
    ]

def sm2_sign_init(key, signer_id=SM2_DEFAULT_ID):
    """初始化签名上下文"""
    ctx = SM2_SIGN_CTX()
    if isinstance(signer_id, str):
        signer_id = signer_id.encode('utf-8')
    ret = gmssl.sm2_sign_init(byref(ctx), byref(key), c_char_p(signer_id), c_size_t(len(signer_id)))
    _check(ret, "sm2_sign_init失败")
    return ctx

def sm2_sign_update(ctx, data):
    """更新签名数据"""
    ret = gmssl.sm2_sign_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm2_sign_update失败")

def sm2_sign_finish(ctx):
    """完成签名，返回DER编码签名"""
    sig = create_string_buffer(SM2_MAX_SIGNATURE_SIZE)
    siglen = c_size_t()
    ret = gmssl.sm2_sign_finish(byref(ctx), sig, byref(siglen))
    _check(ret, "sm2_sign_finish失败")
    return sig[:siglen.value]

def sm2_sign_reset(ctx):
    """重置签名上下文"""
    ret = gmssl.sm2_sign_reset(byref(ctx))
    _check(ret, "sm2_sign_reset失败")

def sm2_sign_finish_fixlen(ctx, siglen):
    """完成签名（固定长度）"""
    sig = create_string_buffer(siglen)
    ret = gmssl.sm2_sign_finish_fixlen(byref(ctx), c_size_t(siglen), sig)
    _check(ret, "sm2_sign_finish_fixlen失败")
    return sig.raw

def sm2_verify_init(key, signer_id=SM2_DEFAULT_ID):
    """初始化验签上下文"""
    ctx = SM2_VERIFY_CTX()
    if isinstance(signer_id, str):
        signer_id = signer_id.encode('utf-8')
    ret = gmssl.sm2_verify_init(byref(ctx), byref(key), c_char_p(signer_id), c_size_t(len(signer_id)))
    _check(ret, "sm2_verify_init失败")
    return ctx

def sm2_verify_update(ctx, data):
    """更新验签数据"""
    ret = gmssl.sm2_verify_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm2_verify_update失败")

def sm2_verify_finish(ctx, sig):
    """完成验签"""
    return gmssl.sm2_verify_finish(byref(ctx), sig, c_size_t(len(sig))) == 1

def sm2_verify_reset(ctx):
    """重置验签上下文"""
    ret = gmssl.sm2_verify_reset(byref(ctx))
    _check(ret, "sm2_verify_reset失败")

# === 加密/解密 ===

def sm2_kdf(data, outlen):
    """SM2 KDF密钥派生函数"""
    out = create_string_buffer(outlen)
    ret = gmssl.sm2_kdf(data, c_size_t(len(data)), c_size_t(outlen), out)
    _check(ret, "sm2_kdf失败")
    return out.raw

def sm2_do_encrypt(key, plaintext):
    """SM2底层加密: 返回SM2_CIPHERTEXT结构"""
    if len(plaintext) > SM2_MAX_PLAINTEXT_SIZE:
        raise ValueError(f"明文不能超过{SM2_MAX_PLAINTEXT_SIZE}字节")
    ct = SM2_CIPHERTEXT()
    ret = gmssl.sm2_do_encrypt(byref(key), plaintext, c_size_t(len(plaintext)), byref(ct))
    _check(ret, "sm2_do_encrypt失败")
    return ct

def sm2_do_decrypt(key, ct):
    """SM2底层解密"""
    out = create_string_buffer(SM2_MAX_PLAINTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_do_decrypt(byref(key), byref(ct), out, byref(outlen))
    _check(ret, "sm2_do_decrypt失败")
    return out[:outlen.value]

def sm2_ciphertext_from_der(data):
    """从 DER 解码密文"""
    ct = SM2_CIPHERTEXT()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_ciphertext_from_der(byref(ct), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_ciphertext_from_der失败")
    return ct

def sm2_encrypt(key, plaintext):
    """SM2加密: 返回DER编码密文"""
    out = create_string_buffer(SM2_MAX_CIPHERTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_encrypt(byref(key), plaintext, c_size_t(len(plaintext)), out, byref(outlen))
    _check(ret, "sm2_encrypt失败")
    return out[:outlen.value]

def sm2_decrypt(key, ciphertext):
    """SM2解密: 输入DER编码密文"""
    out = create_string_buffer(SM2_MAX_PLAINTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_decrypt(byref(key), ciphertext, c_size_t(len(ciphertext)), out, byref(outlen))
    _check(ret, "sm2_decrypt失败")
    return out[:outlen.value]

def sm2_do_encrypt_fixlen(key, plaintext, point_size):
    """SM2定长加密"""
    if len(plaintext) > SM2_MAX_PLAINTEXT_SIZE:
        raise ValueError(f"明文不能超过{SM2_MAX_PLAINTEXT_SIZE}字节")
    ct = SM2_CIPHERTEXT()
    ret = gmssl.sm2_do_encrypt_fixlen(byref(key), plaintext, c_size_t(len(plaintext)), c_int(point_size), byref(ct))
    _check(ret, "sm2_do_encrypt_fixlen失败")
    return ct

def sm2_encrypt_fixlen(key, plaintext, point_size):
    """SM2定长加密: 返回DER编码密文"""
    out = create_string_buffer(SM2_MAX_CIPHERTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_encrypt_fixlen(byref(key), plaintext, c_size_t(len(plaintext)), c_int(point_size), out, byref(outlen))
    _check(ret, "sm2_encrypt_fixlen失败")
    return out[:outlen.value]

# -- 预计算加密 --
def sm2_encrypt_pre_compute():
    """预计算加密参数"""
    pre_comp = (SM2_ENC_PRE_COMP * SM2_ENC_PRE_COMP_NUM)()
    ret = gmssl.sm2_encrypt_pre_compute(pre_comp)
    _check(ret, "sm2_encrypt_pre_compute失败")
    return pre_comp

def sm2_do_encrypt_ex(key, pre_comp, plaintext):
    """使用预计算参数的加密"""
    ct = SM2_CIPHERTEXT()
    ret = gmssl.sm2_do_encrypt_ex(byref(key), pre_comp, plaintext, c_size_t(len(plaintext)), byref(ct))
    _check(ret, "sm2_do_encrypt_ex失败")
    return ct

# -- 流式加密 --
class SM2_ENC_CTX(Structure):
    _fields_ = [
        ("pre_comp", SM2_ENC_PRE_COMP * SM2_ENC_PRE_COMP_NUM),
        ("pre_comp_num", c_size_t),
        ("buf", c_uint8 * SM2_MAX_PLAINTEXT_SIZE),
        ("buf_size", c_size_t),
    ]

class SM2_DEC_CTX(Structure):
    _fields_ = [
        ("buf", c_uint8 * SM2_MAX_CIPHERTEXT_SIZE),
        ("buf_size", c_size_t),
    ]

def sm2_encrypt_init():
    """初始化加密上下文"""
    ctx = SM2_ENC_CTX()
    ret = gmssl.sm2_encrypt_init(byref(ctx))
    _check(ret, "sm2_encrypt_init失败")
    return ctx

def sm2_encrypt_update(ctx, data):
    """更新加密数据"""
    ret = gmssl.sm2_encrypt_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm2_encrypt_update失败")

def sm2_encrypt_finish(ctx, public_key):
    """完成加密，返回DER编码密文"""
    out = create_string_buffer(SM2_MAX_CIPHERTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_encrypt_finish(byref(ctx), byref(public_key), out, byref(outlen))
    _check(ret, "sm2_encrypt_finish失败")
    return out[:outlen.value]

def sm2_encrypt_reset(ctx):
    """重置加密上下文"""
    ret = gmssl.sm2_encrypt_reset(byref(ctx))
    _check(ret, "sm2_encrypt_reset失败")

def sm2_decrypt_init():
    """初始化解密上下文"""
    ctx = SM2_DEC_CTX()
    ret = gmssl.sm2_decrypt_init(byref(ctx))
    _check(ret, "sm2_decrypt_init失败")
    return ctx

def sm2_decrypt_update(ctx, data):
    """更新解密数据"""
    ret = gmssl.sm2_decrypt_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm2_decrypt_update失败")

def sm2_decrypt_finish(ctx, key):
    """完成解密"""
    out = create_string_buffer(SM2_MAX_PLAINTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm2_decrypt_finish(byref(ctx), byref(key), out, byref(outlen))
    _check(ret, "sm2_decrypt_finish失败")
    return out[:outlen.value]

def sm2_decrypt_reset(ctx):
    """重置解密上下文"""
    ret = gmssl.sm2_decrypt_reset(byref(ctx))
    _check(ret, "sm2_decrypt_reset失败")

# === ECDH 密钥交换 ===

def sm2_do_ecdh(key, peer_key):
    """SM2 ECDH: 计算共享密钥，返回32字节"""
    out = (c_uint8 * 32)()
    ret = gmssl.sm2_do_ecdh(byref(key), byref(peer_key), out)
    _check(ret, "sm2_do_ecdh失败")
    return bytes(out)

def sm2_ecdh(key, uncompressed_point):
    """SM2 ECDH: 使用非压缩公钥点计算共享密钥"""
    if len(uncompressed_point) != 65:
        raise ValueError(f"需要65字节非压缩点，实际{len(uncompressed_point)}字节")
    out = (c_uint8 * 32)()
    ret = gmssl.sm2_ecdh(byref(key), (c_uint8 * 65)(*uncompressed_point), out)
    _check(ret, "sm2_ecdh失败")
    return bytes(out)