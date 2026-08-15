# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm9.py - SM9 标识密码接口
# 封装 sm9.h 中定义的所有SM9函数
# 包括: 签名/验签、加密/解密、密钥交换

from ctypes import *
from . import gmssl, libc, _check
from .sm9_z256 import Sm9Point, Sm9TwistPoint, Fp2, Fp4, Fp12
from .error import NativeError, StateError

# === SM3 CTX（内部使用） ===
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

# === SM9 常量 ===
SM9_HID_SIGN = 0x01
SM9_HID_EXCH = 0x02
SM9_HID_ENC = 0x03
SM9_HASH1_PREFIX = 0x01
SM9_HASH2_PREFIX = 0x02
SM9_MAX_ID_SIZE = 63
SM9_MAX_PLAINTEXT_SIZE = 255
SM9_MAX_CIPHERTEXT_SIZE = 367
SM9_SIGNATURE_SIZE = 104
SM9_SIGN_MASTER_KEY_MAX_SIZE = 171
SM9_SIGN_MASTER_PUBLIC_KEY_BYTES = 129
SM9_SIGN_MASTER_PUBLIC_KEY_SIZE = 136
SM9_SIGN_KEY_SIZE = 204
SM9_ENC_MASTER_KEY_MAX_SIZE = 105
SM9_ENC_MASTER_PUBLIC_KEY_BYTES = 65
SM9_ENC_MASTER_PUBLIC_KEY_SIZE = 70
SM9_ENC_KEY_SIZE = 204
SM9_MAX_PRIVATE_KEY_SIZE = 204
SM9_MAX_PRIVATE_KEY_INFO_SIZE = 512
SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE = 1024

# === z256_hash1 ===
def sm9_z256_hash1(identity, hid):
    """SM9密码杂凑函数H1: 计算h1 = H1(ID||hid, N)"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    h1 = (c_uint64 * 4)()
    ret = gmssl.sm9_z256_hash1(h1, c_char_p(identity), c_size_t(len(identity)), c_uint8(hid))
    _check(ret, "sm9_z256_hash1失败")
    return h1

# === OID 相关 ===
def sm9_oid_name(oid):
    """获取SM9 OID名称，无效OID返回None"""
    gmssl.sm9_oid_name.restype = c_char_p
    result = gmssl.sm9_oid_name(c_int(oid))
    return result.decode('ascii') if result else None

def sm9_oid_from_name(name):
    """从名称获取SM9 OID"""
    return gmssl.sm9_oid_from_name(name.encode('ascii'))

# ========== SM9 签名 ==========

class SM9_SIGN_MASTER_KEY(Structure):
    _fields_ = [
        ("Ppubs", Sm9TwistPoint),
        ("ks", c_uint64 * 4),
    ]

class SM9_SIGN_KEY(Structure):
    _fields_ = [
        ("Ppubs", Sm9TwistPoint),
        ("ds", Sm9Point),
    ]

class SM9_SIGNATURE(Structure):
    _fields_ = [
        ("h", c_uint64 * 4),
        ("S", Sm9Point),
    ]

class SM9_SIGN_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
    ]

# -- 签名主密钥 --
def sm9_sign_master_key_generate(master_key=None):
    """生成SM9签名主密钥对"""
    if master_key is None:
        master_key = SM9_SIGN_MASTER_KEY()
    ret = gmssl.sm9_sign_master_key_generate(byref(master_key))
    _check(ret, "sm9_sign_master_key_generate失败")
    return master_key

def sm9_sign_master_key_extract_key(master, identity):
    """从签名主密钥提取用户签名私钥"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    key = SM9_SIGN_KEY()
    ret = gmssl.sm9_sign_master_key_extract_key(
        byref(master), c_char_p(identity), c_size_t(len(identity)), byref(key))
    _check(ret, "sm9_sign_master_key_extract_key失败")
    return key

def sm9_sign_master_key_from_der(data):
    """从 DER 解码签名主密钥"""
    master = SM9_SIGN_MASTER_KEY()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_sign_master_key_from_der(byref(master), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_sign_master_key_from_der失败")
    return master

def sm9_sign_master_public_key_from_der(master, data):
    """从 DER 解码签名主公钥"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_sign_master_public_key_from_der(byref(master), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_sign_master_public_key_from_der失败")

# -- 签名密钥 --
def sm9_sign_key_from_der(data):
    """从 DER 解码签名密钥"""
    key = SM9_SIGN_KEY()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_sign_key_from_der(byref(key), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_sign_key_from_der失败")
    return key

# -- 签名/验签 底层 --
def sm9_do_sign(key, sm3_ctx):
    """SM9底层签名: 对已完成的SM3上下文进行签名"""
    sig = SM9_SIGNATURE()
    ret = gmssl.sm9_do_sign(byref(key), byref(sm3_ctx), byref(sig))
    _check(ret, "sm9_do_sign失败")
    return sig

def sm9_do_verify(mpk, identity, sm3_ctx, sig):
    """SM9底层验签"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    ret = gmssl.sm9_do_verify(
        byref(mpk), c_char_p(identity), c_size_t(len(identity)),
        byref(sm3_ctx), byref(sig))
    return ret == 1

def sm9_signature_from_der(data):
    """从 DER 解码签名"""
    sig = SM9_SIGNATURE()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_signature_from_der(byref(sig), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_signature_from_der失败")
    return sig

# -- 签名/验签 流式接口 --
def sm9_sign_init():
    """初始化SM9签名上下文"""
    ctx = SM9_SIGN_CTX()
    ret = gmssl.sm9_sign_init(byref(ctx))
    _check(ret, "sm9_sign_init失败")
    return ctx

def sm9_sign_update(ctx, data):
    """更新SM9签名数据"""
    ret = gmssl.sm9_sign_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm9_sign_update失败")

def sm9_sign_finish(ctx, key):
    """完成SM9签名，返回DER编码签名"""
    sig = create_string_buffer(SM9_SIGNATURE_SIZE)
    siglen = c_size_t()
    ret = gmssl.sm9_sign_finish(byref(ctx), byref(key), sig, byref(siglen))
    _check(ret, "sm9_sign_finish失败")
    return sig[:siglen.value]

def sm9_verify_init():
    """初始化SM9验签上下文"""
    ctx = SM9_SIGN_CTX()
    ret = gmssl.sm9_verify_init(byref(ctx))
    _check(ret, "sm9_verify_init失败")
    return ctx

def sm9_verify_update(ctx, data):
    """更新SM9验签数据"""
    ret = gmssl.sm9_verify_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm9_verify_update失败")

def sm9_verify_finish(ctx, sig, mpk, identity):
    """完成SM9验签"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    ret = gmssl.sm9_verify_finish(
        byref(ctx), sig, c_size_t(len(sig)),
        byref(mpk), c_char_p(identity), c_size_t(len(identity)))
    return ret == 1

# ========== SM9 加密 ==========

class SM9_ENC_MASTER_KEY(Structure):
    _fields_ = [
        ("Ppube", Sm9Point),
        ("ke", c_uint64 * 4),
    ]

class SM9_ENC_KEY(Structure):
    _fields_ = [
        ("Ppube", Sm9Point),
        ("de", Sm9TwistPoint),
    ]

# -- 加密主密钥 --
def sm9_enc_master_key_generate(master_key=None):
    """生成SM9加密主密钥对"""
    if master_key is None:
        master_key = SM9_ENC_MASTER_KEY()
    ret = gmssl.sm9_enc_master_key_generate(byref(master_key))
    _check(ret, "sm9_enc_master_key_generate失败")
    return master_key

def sm9_enc_master_key_extract_key(master, identity):
    """从加密主密钥提取用户加密私钥"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    key = SM9_ENC_KEY()
    ret = gmssl.sm9_enc_master_key_extract_key(
        byref(master), c_char_p(identity), c_size_t(len(identity)), byref(key))
    _check(ret, "sm9_enc_master_key_extract_key失败")
    return key

def sm9_enc_master_key_from_der(data):
    """从 DER 解码加密主密钥"""
    master = SM9_ENC_MASTER_KEY()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_enc_master_key_from_der(byref(master), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_enc_master_key_from_der失败")
    return master

def sm9_enc_master_public_key_from_der(master, data):
    """从 DER 解码加密主公钥"""
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_enc_master_public_key_from_der(byref(master), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_enc_master_public_key_from_der失败")

# -- 加密密钥 --
def sm9_enc_key_from_der(data):
    """从 DER 解码加密密钥"""
    key = SM9_ENC_KEY()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_enc_key_from_der(byref(key), byref(in_ptr), byref(inlen))
    _check(ret, "sm9_enc_key_from_der失败")
    return key

# -- KEM (密钥封装) --
def sm9_kem_encrypt(mpk, identity, klen):
    """SM9 KEM加密: 封装密钥"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    kbuf = create_string_buffer(klen)
    C = Sm9Point()
    ret = gmssl.sm9_kem_encrypt(
        byref(mpk), c_char_p(identity), c_size_t(len(identity)),
        c_size_t(klen), kbuf, byref(C))
    _check(ret, "sm9_kem_encrypt失败")
    return kbuf.raw, C

def sm9_kem_decrypt(key, identity, C, klen):
    """SM9 KEM解密: 解封密钥"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    kbuf = create_string_buffer(klen)
    ret = gmssl.sm9_kem_decrypt(
        byref(key), c_char_p(identity), c_size_t(len(identity)),
        byref(C), c_size_t(klen), kbuf)
    _check(ret, "sm9_kem_decrypt失败")
    return kbuf.raw

# -- 加密/解密 底层 --
def sm9_do_encrypt(mpk, identity, plaintext):
    """SM9底层加密: 直接加密任意长度数据"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    C1 = Sm9Point()
    c2 = create_string_buffer(len(plaintext))
    c3 = create_string_buffer(32)  # SM3_HMAC_SIZE
    ret = gmssl.sm9_do_encrypt(
        byref(mpk), c_char_p(identity), c_size_t(len(identity)),
        plaintext, c_size_t(len(plaintext)), byref(C1), c2, c3)
    _check(ret, "sm9_do_encrypt失败")
    return C1, c2.raw[:len(plaintext)], c3.raw

def sm9_do_decrypt(key, identity, C1, c2, c3):
    """SM9底层解密"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    out = create_string_buffer(len(c2))
    ret = gmssl.sm9_do_decrypt(
        byref(key), c_char_p(identity), c_size_t(len(identity)),
        byref(C1), c2, c_size_t(len(c2)), c3, out)
    _check(ret, "sm9_do_decrypt失败")
    return out.raw[:len(c2)]

# -- 加密/解密 整体接口 --
def sm9_encrypt(mpk, identity, plaintext):
    """SM9加密: 返回DER编码密文"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    out = create_string_buffer(SM9_MAX_CIPHERTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm9_encrypt(
        byref(mpk), c_char_p(identity), c_size_t(len(identity)),
        plaintext, c_size_t(len(plaintext)), out, byref(outlen))
    _check(ret, "sm9_encrypt失败")
    return out[:outlen.value]

def sm9_decrypt(key, identity, ciphertext):
    """SM9解密: 输入DER编码密文"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    out = create_string_buffer(SM9_MAX_PLAINTEXT_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm9_decrypt(
        byref(key), c_char_p(identity), c_size_t(len(identity)),
        ciphertext, c_size_t(len(ciphertext)), out, byref(outlen))
    _check(ret, "sm9_decrypt失败")
    return out[:outlen.value]

def sm9_ciphertext_from_der(data):
    """从 DER 解码密文"""
    C1 = Sm9Point()
    c2_ptr = c_void_p()
    c2len = c_size_t()
    c3_ptr = c_void_p()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm9_ciphertext_from_der(
        byref(C1), byref(c2_ptr), byref(c2len), byref(c3_ptr),
        byref(in_ptr), byref(inlen))
    _check(ret, "sm9_ciphertext_from_der失败")
    c2 = create_string_buffer(c2len.value)
    libc.memcpy(c2, c2_ptr, c2len)
    c3 = create_string_buffer(32)
    libc.memcpy(c3, c3_ptr, 32)
    return C1, c2.raw, c3.raw

# ========== SM9 密钥交换 ==========

# SM9_EXCH_MASTER_KEY = SM9_ENC_MASTER_KEY (别名)
# SM9_EXCH_KEY = SM9_ENC_KEY (别名)

sm9_exch_master_key_generate = sm9_enc_master_key_generate

def sm9_exch_master_key_extract_key(master, identity):
    """从交换主密钥提取用户密钥（HID=0x02）"""
    if isinstance(identity, str):
        identity = identity.encode('utf-8')
    key = SM9_ENC_KEY()  # SM9_EXCH_KEY = SM9_ENC_KEY
    ret = gmssl.sm9_exch_master_key_extract_key(
        byref(master), c_char_p(identity), c_size_t(len(identity)), byref(key))
    _check(ret, "sm9_exch_master_key_extract_key失败")
    return key

def sm9_exch_step_1A(mpk, idB):
    """密钥交换第1步A: 生成RA和rA"""
    if isinstance(idB, str):
        idB = idB.encode('utf-8')
    RA = Sm9Point()
    rA = (c_uint64 * 4)()
    ret = gmssl.sm9_exch_step_1A(
        byref(mpk), c_char_p(idB), c_size_t(len(idB)), byref(RA), rA)
    _check(ret, "sm9_exch_step_1A失败")
    return RA, rA

def sm9_exch_step_1B(mpk, idA, idB, key, RA):
    """密钥交换第1步B: 生成RB和共享密钥sk"""
    if isinstance(idA, str):
        idA = idA.encode('utf-8')
    if isinstance(idB, str):
        idB = idB.encode('utf-8')
    RB = Sm9Point()
    sk = create_string_buffer(32)  # 默认32字节密钥
    ret = gmssl.sm9_exch_step_1B(
        byref(mpk), c_char_p(idA), c_size_t(len(idA)),
        c_char_p(idB), c_size_t(len(idB)),
        byref(key), byref(RA), byref(RB), sk, c_size_t(32))
    _check(ret, "sm9_exch_step_1B失败")
    return RB, sk.raw

def sm9_exch_step_2A(mpk, idA, idB, key, rA, RA, RB):
    """密钥交换第2步A: 计算共享密钥sk"""
    if isinstance(idA, str):
        idA = idA.encode('utf-8')
    if isinstance(idB, str):
        idB = idB.encode('utf-8')
    sk = create_string_buffer(32)
    ret = gmssl.sm9_exch_step_2A(
        byref(mpk), c_char_p(idA), c_size_t(len(idA)),
        c_char_p(idB), c_size_t(len(idB)),
        byref(key), rA, byref(RA), byref(RB), sk, c_size_t(32))
    _check(ret, "sm9_exch_step_2A失败")
    return sk.raw