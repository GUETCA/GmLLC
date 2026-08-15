# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm4.py - SM4 分组密码接口
# 封装 sm4.h 中定义的所有SM4函数
# 包括: ECB、CBC、CTR、GCM、CFB、OFB、CCM、XTS 等模式

from ctypes import *
from . import gmssl, _check
from .error import NativeError, StateError

# === 常量 ===
SM4_KEY_SIZE = 16
SM4_BLOCK_SIZE = 16
SM4_NUM_ROUNDS = 32

# GCM 常量
SM4_GCM_MIN_IV_SIZE = 1
SM4_GCM_MAX_IV_SIZE = 64
SM4_GCM_DEFAULT_IV_SIZE = 12
SM4_GCM_MAX_TAG_SIZE = 16
SM4_GCM_MIN_TAG_SIZE = 12
SM4_GCM_DEFAULT_TAG_SIZE = 16

# === GHASH 内部结构 ===
class gf128_t(Structure):
    _fields_ = [
        ("hi", c_uint64),
        ("lo", c_uint64),
    ]

class GHASH_CTX(Structure):
    _fields_ = [
        ("H", gf128_t),
        ("X", gf128_t),
        ("aadlen", c_size_t),
        ("clen", c_size_t),
        ("block", c_uint8 * 16),
        ("num", c_size_t),
    ]

# === SM4 密钥 ===

class SM4_KEY(Structure):
    _fields_ = [
        ("rk", c_uint32 * SM4_NUM_ROUNDS),
    ]

def sm4_set_encrypt_key(raw_key):
    """设置SM4加密密钥"""
    if len(raw_key) != SM4_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{SM4_KEY_SIZE}字节")
    key = SM4_KEY()
    gmssl.sm4_set_encrypt_key(byref(key), (c_uint8 * SM4_KEY_SIZE)(*raw_key))
    return key

def sm4_set_decrypt_key(raw_key):
    """设置SM4解密密钥"""
    if len(raw_key) != SM4_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{SM4_KEY_SIZE}字节")
    key = SM4_KEY()
    gmssl.sm4_set_decrypt_key(byref(key), (c_uint8 * SM4_KEY_SIZE)(*raw_key))
    return key

def sm4_encrypt(key, block):
    """SM4单块加密"""
    if len(block) != SM4_BLOCK_SIZE:
        raise ValueError(f"块长度必须为{SM4_BLOCK_SIZE}字节")
    out = (c_uint8 * SM4_BLOCK_SIZE)()
    gmssl.sm4_encrypt(byref(key), (c_uint8 * SM4_BLOCK_SIZE)(*block), out)
    return bytes(out)

# -- 批量块加密 --
def sm4_encrypt_blocks(key, data):
    """SM4 ECB批量加密块"""
    nblocks = len(data) // SM4_BLOCK_SIZE
    out = create_string_buffer(nblocks * SM4_BLOCK_SIZE)
    gmssl.sm4_encrypt_blocks(byref(key), data, c_size_t(nblocks), out)
    return out.raw

def sm4_cbc_encrypt_blocks(key, iv, data):
    """SM4 CBC批量加密块"""
    nblocks = len(data) // SM4_BLOCK_SIZE
    iv_arr = (c_uint8 * SM4_BLOCK_SIZE)(*iv)
    out = create_string_buffer(nblocks * SM4_BLOCK_SIZE)
    gmssl.sm4_cbc_encrypt_blocks(byref(key), iv_arr, data, c_size_t(nblocks), out)
    return bytes(iv_arr), out.raw

def sm4_cbc_decrypt_blocks(key, iv, data):
    """SM4 CBC批量解密块"""
    nblocks = len(data) // SM4_BLOCK_SIZE
    iv_arr = (c_uint8 * SM4_BLOCK_SIZE)(*iv)
    out = create_string_buffer(nblocks * SM4_BLOCK_SIZE)
    gmssl.sm4_cbc_decrypt_blocks(byref(key), iv_arr, data, c_size_t(nblocks), out)
    return bytes(iv_arr), out.raw

def sm4_ctr_encrypt_blocks(key, ctr, data):
    """SM4 CTR批量加密块"""
    nblocks = len(data) // SM4_BLOCK_SIZE
    ctr_arr = (c_uint8 * 16)(*ctr)
    out = create_string_buffer(nblocks * SM4_BLOCK_SIZE)
    gmssl.sm4_ctr_encrypt_blocks(byref(key), ctr_arr, data, c_size_t(nblocks), out)
    return bytes(ctr_arr), out.raw

def sm4_ctr32_encrypt_blocks(key, ctr, data):
    """SM4 CTR32批量加密块"""
    nblocks = len(data) // SM4_BLOCK_SIZE
    ctr_arr = (c_uint8 * 16)(*ctr)
    out = create_string_buffer(nblocks * SM4_BLOCK_SIZE)
    gmssl.sm4_ctr32_encrypt_blocks(byref(key), ctr_arr, data, c_size_t(nblocks), out)
    return bytes(ctr_arr), out.raw

# -- CBC Padding 模式 --
def sm4_cbc_padding_encrypt(key, iv, data):
    """SM4 CBC PKCS#7 Padding加密"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_padding_encrypt(
        byref(key), (c_uint8 * SM4_BLOCK_SIZE)(*iv),
        data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_cbc_padding_encrypt失败")
    return out[:outlen.value]

def sm4_cbc_padding_decrypt(key, iv, data):
    """SM4 CBC PKCS#7 Padding解密"""
    out = create_string_buffer(len(data))
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_padding_decrypt(
        byref(key), (c_uint8 * SM4_BLOCK_SIZE)(*iv),
        data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_cbc_padding_decrypt失败")
    return out[:outlen.value]

def sm4_ctr_encrypt(key, ctr, data):
    """SM4 CTR流式加密"""
    ctr_arr = (c_uint8 * 16)(*ctr)
    out = create_string_buffer(len(data))
    gmssl.sm4_ctr_encrypt(byref(key), ctr_arr, data, c_size_t(len(data)), out)
    return bytes(ctr_arr), out.raw

def sm4_ctr32_encrypt(key, ctr, data):
    """SM4 CTR32流式加密"""
    ctr_arr = (c_uint8 * 16)(*ctr)
    out = create_string_buffer(len(data))
    gmssl.sm4_ctr32_encrypt(byref(key), ctr_arr, data, c_size_t(len(data)), out)
    return bytes(ctr_arr), out.raw

# === CBC 流式上下文 ===

class SM4_CBC_CTX(Structure):
    _fields_ = [
        ("sm4_key", SM4_KEY),
        ("iv", c_uint8 * SM4_BLOCK_SIZE),
        ("block", c_uint8 * SM4_BLOCK_SIZE),
        ("block_nbytes", c_size_t),
    ]

def sm4_cbc_encrypt_init(key, iv):
    """初始化SM4 CBC加密上下文"""
    ctx = SM4_CBC_CTX()
    ret = gmssl.sm4_cbc_encrypt_init(
        byref(ctx), (c_uint8 * SM4_KEY_SIZE)(*key), (c_uint8 * SM4_BLOCK_SIZE)(*iv))
    _check(ret, "sm4_cbc_encrypt_init失败")
    return ctx

def sm4_cbc_encrypt_update(ctx, data):
    """更新SM4 CBC加密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_encrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_cbc_encrypt_update失败")
    return out[:outlen.value]

def sm4_cbc_encrypt_finish(ctx):
    """完成SM4 CBC加密"""
    out = create_string_buffer(SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_encrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_cbc_encrypt_finish失败")
    return out[:outlen.value]

def sm4_cbc_decrypt_init(key, iv):
    """初始化SM4 CBC解密上下文"""
    ctx = SM4_CBC_CTX()
    ret = gmssl.sm4_cbc_decrypt_init(
        byref(ctx), (c_uint8 * SM4_KEY_SIZE)(*key), (c_uint8 * SM4_BLOCK_SIZE)(*iv))
    _check(ret, "sm4_cbc_decrypt_init失败")
    return ctx

def sm4_cbc_decrypt_update(ctx, data):
    """更新SM4 CBC解密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_decrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_cbc_decrypt_update失败")
    return out[:outlen.value]

def sm4_cbc_decrypt_finish(ctx):
    """完成SM4 CBC解密"""
    out = create_string_buffer(SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_cbc_decrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_cbc_decrypt_finish失败")
    return out[:outlen.value]

# === CTR 流式上下文 ===

class SM4_CTR_CTX(Structure):
    _fields_ = [
        ("sm4_key", SM4_KEY),
        ("ctr", c_uint8 * SM4_BLOCK_SIZE),
        ("block", c_uint8 * SM4_BLOCK_SIZE),
        ("block_nbytes", c_size_t),
    ]

def sm4_ctr_encrypt_init(key, ctr):
    """初始化SM4 CTR加密上下文"""
    ctx = SM4_CTR_CTX()
    ret = gmssl.sm4_ctr_encrypt_init(
        byref(ctx), (c_uint8 * SM4_KEY_SIZE)(*key), (c_uint8 * SM4_BLOCK_SIZE)(*ctr))
    _check(ret, "sm4_ctr_encrypt_init失败")
    return ctx

def sm4_ctr_encrypt_update(ctx, data):
    """更新SM4 CTR加密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_ctr_encrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_ctr_encrypt_update失败")
    return out[:outlen.value]

def sm4_ctr_encrypt_finish(ctx):
    """完成SM4 CTR加密"""
    out = create_string_buffer(SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_ctr_encrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_ctr_encrypt_finish失败")
    return out[:outlen.value]

def sm4_ctr32_encrypt_init(key, ctr):
    """初始化SM4 CTR32加密上下文"""
    ctx = SM4_CTR_CTX()
    ret = gmssl.sm4_ctr32_encrypt_init(
        byref(ctx), (c_uint8 * SM4_KEY_SIZE)(*key), (c_uint8 * SM4_BLOCK_SIZE)(*ctr))
    _check(ret, "sm4_ctr32_encrypt_init失败")
    return ctx

def sm4_ctr32_encrypt_update(ctx, data):
    """更新SM4 CTR32加密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_ctr32_encrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_ctr32_encrypt_update失败")
    return out[:outlen.value]

def sm4_ctr32_encrypt_finish(ctx):
    """完成SM4 CTR32加密"""
    out = create_string_buffer(SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_ctr32_encrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_ctr32_encrypt_finish失败")
    return out[:outlen.value]

# === GCM 模式 ===

class SM4_GCM_CTX(Structure):
    _fields_ = [
        ("enc_ctx", SM4_CTR_CTX),
        ("mac_ctx", GHASH_CTX),
        ("Y", c_uint8 * 16),
        ("taglen", c_size_t),
        ("mac", c_uint8 * 16),
        ("maclen", c_size_t),
        ("encedlen", c_uint64),
    ]

def sm4_gcm_encrypt(key, iv, aad, plaintext, taglen=SM4_GCM_DEFAULT_TAG_SIZE):
    """SM4 GCM加密: 一次性接口"""
    out = create_string_buffer(len(plaintext))
    tag = create_string_buffer(taglen)
    ret = gmssl.sm4_gcm_encrypt(
        byref(key), iv, c_size_t(len(iv)), aad, c_size_t(len(aad)),
        plaintext, c_size_t(len(plaintext)), out, c_size_t(taglen), tag)
    _check(ret, "sm4_gcm_encrypt失败")
    return out.raw, tag.raw

def sm4_gcm_decrypt(key, iv, aad, ciphertext, tag):
    """SM4 GCM解密: 一次性接口"""
    out = create_string_buffer(len(ciphertext))
    ret = gmssl.sm4_gcm_decrypt(
        byref(key), iv, c_size_t(len(iv)), aad, c_size_t(len(aad)),
        ciphertext, c_size_t(len(ciphertext)), tag, c_size_t(len(tag)), out)
    _check(ret, "sm4_gcm_decrypt失败")
    return out.raw

def sm4_gcm_encrypt_init(key, keylen, iv, aad, taglen=SM4_GCM_DEFAULT_TAG_SIZE):
    """初始化SM4 GCM加密上下文"""
    ctx = SM4_GCM_CTX()
    ret = gmssl.sm4_gcm_encrypt_init(
        byref(ctx), key, c_size_t(keylen), iv, c_size_t(len(iv)),
        aad, c_size_t(len(aad)), c_size_t(taglen))
    _check(ret, "sm4_gcm_encrypt_init失败")
    return ctx

def sm4_gcm_encrypt_update(ctx, data):
    """更新SM4 GCM加密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_gcm_encrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_gcm_encrypt_update失败")
    return out[:outlen.value]

def sm4_gcm_encrypt_finish(ctx):
    """完成SM4 GCM加密"""
    out = create_string_buffer(SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_gcm_encrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_gcm_encrypt_finish失败")
    return out[:outlen.value]

def sm4_gcm_decrypt_init(key, keylen, iv, aad, taglen=SM4_GCM_DEFAULT_TAG_SIZE):
    """初始化SM4 GCM解密上下文"""
    ctx = SM4_GCM_CTX()
    ret = gmssl.sm4_gcm_decrypt_init(
        byref(ctx), key, c_size_t(keylen), iv, c_size_t(len(iv)),
        aad, c_size_t(len(aad)), c_size_t(taglen))
    _check(ret, "sm4_gcm_decrypt_init失败")
    return ctx

def sm4_gcm_decrypt_update(ctx, data):
    """更新SM4 GCM解密数据"""
    out = create_string_buffer(len(data) + SM4_BLOCK_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_gcm_decrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "sm4_gcm_decrypt_update失败")
    return out[:outlen.value]

def sm4_gcm_decrypt_finish(ctx):
    """完成SM4 GCM解密"""
    out = create_string_buffer(SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE)
    outlen = c_size_t()
    ret = gmssl.sm4_gcm_decrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "sm4_gcm_decrypt_finish失败")
    return out[:outlen.value]


# === 便捷封装类 ===

class Sm4Ecb:
    """SM4 ECB 模式"""
    def __init__(self, key, encrypt=True):
        if encrypt:
            self.key = sm4_set_encrypt_key(key)
        else:
            self.key = sm4_set_decrypt_key(key)

    def encrypt(self, block):
        return sm4_encrypt(self.key, block)


class Sm4Cbc:
    """SM4 CBC 模式"""
    def __init__(self, key, iv, encrypt=True):
        self._encrypt = encrypt
        if encrypt:
            self.ctx = sm4_cbc_encrypt_init(key, iv)
        else:
            self.ctx = sm4_cbc_decrypt_init(key, iv)

    def update(self, data):
        if self._encrypt:
            return sm4_cbc_encrypt_update(self.ctx, data)
        else:
            return sm4_cbc_decrypt_update(self.ctx, data)

    def finish(self):
        if self._encrypt:
            return sm4_cbc_encrypt_finish(self.ctx)
        else:
            return sm4_cbc_decrypt_finish(self.ctx)


class Sm4Ctr:
    """SM4 CTR 模式"""
    def __init__(self, key, ctr):
        self.ctx = sm4_ctr_encrypt_init(key, ctr)

    def update(self, data):
        return sm4_ctr_encrypt_update(self.ctx, data)

    def finish(self):
        return sm4_ctr_encrypt_finish(self.ctx)


class Sm4Gcm:
    """SM4 GCM 模式"""
    def __init__(self, key, iv, aad, taglen=SM4_GCM_DEFAULT_TAG_SIZE, encrypt=True):
        self._encrypt = encrypt
        if encrypt:
            self.ctx = sm4_gcm_encrypt_init(key, SM4_KEY_SIZE, iv, aad, taglen)
        else:
            self.ctx = sm4_gcm_decrypt_init(key, SM4_KEY_SIZE, iv, aad, taglen)

    def update(self, data):
        if self._encrypt:
            return sm4_gcm_encrypt_update(self.ctx, data)
        else:
            return sm4_gcm_decrypt_update(self.ctx, data)

    def finish(self):
        if self._encrypt:
            return sm4_gcm_encrypt_finish(self.ctx)
        else:
            return sm4_gcm_decrypt_finish(self.ctx)