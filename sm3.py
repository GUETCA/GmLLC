# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm3.py - SM3 密码杂凑算法接口
# 封装 sm3.h 中定义的所有SM3函数
# 包括: 哈希、HMAC、KDF、PBKDF2

from ctypes import *
from . import gmssl, _check
from .error import NativeError, StateError

# === 常量 ===
SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64
SM3_STATE_WORDS = 8
SM3_HMAC_SIZE = 32
SM3_PBKDF2_MIN_ITER = 10000
SM3_PBKDF2_MAX_ITER = 16777216 - 1
SM3_PBKDF2_MAX_SALT_SIZE = 64
SM3_PBKDF2_DEFAULT_SALT_SIZE = 8

# === SM3 上下文 ===

class SM3_CTX(Structure):
    _fields_ = [
        ("digest", c_uint32 * SM3_STATE_WORDS),
        ("nblocks", c_uint64),
        ("block", c_uint8 * SM3_BLOCK_SIZE),
        ("num", c_size_t),
    ]

def sm3_compress_blocks(digest, data, blocks):
    """SM3块压缩: 直接压缩指定数量的块，结果会写回digest"""
    if isinstance(digest, (list, tuple)):
        dgst_arr = (c_uint32 * 8)(*digest)
        gmssl.sm3_compress_blocks(dgst_arr, data, c_size_t(blocks))
        for i in range(8):
            digest[i] = dgst_arr[i]
    else:
        dgst_arr = (c_uint32 * 8)(*[0]*8)
        gmssl.sm3_compress_blocks(dgst_arr, data, c_size_t(blocks))

def sm3_init():
    """初始化SM3上下文"""
    ctx = SM3_CTX()
    gmssl.sm3_init(byref(ctx))
    return ctx

def sm3_update(ctx, data):
    """更新SM3哈希数据"""
    gmssl.sm3_update(byref(ctx), data, c_size_t(len(data)))

def sm3_finish(ctx):
    """完成SM3哈希，返回32字节摘要"""
    dgst = (c_uint8 * SM3_DIGEST_SIZE)()
    gmssl.sm3_finish(byref(ctx), dgst)
    return bytes(dgst)


class Sm3:
    """SM3 哈希便捷类"""
    def __init__(self):
        self.ctx = sm3_init()

    def reset(self):
        gmssl.sm3_init(byref(self.ctx))

    def update(self, data):
        sm3_update(self.ctx, data)

    def digest(self):
        return sm3_finish(self.ctx)

    def copy(self):
        """复制当前上下文状态"""
        new = Sm3.__new__(Sm3)
        new.ctx = SM3_CTX()
        from . import libc
        libc.memcpy(byref(new.ctx), byref(self.ctx), sizeof(SM3_CTX))
        return new


# === SM3 HMAC ===

class SM3_HMAC_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
        ("key", c_uint8 * SM3_BLOCK_SIZE),
    ]

def sm3_hmac_init(key):
    """初始化SM3 HMAC"""
    ctx = SM3_HMAC_CTX()
    gmssl.sm3_hmac_init(byref(ctx), key, c_size_t(len(key)))
    return ctx

def sm3_hmac_update(ctx, data):
    """更新SM3 HMAC数据"""
    gmssl.sm3_hmac_update(byref(ctx), data, c_size_t(len(data)))

def sm3_hmac_finish(ctx):
    """完成SM3 HMAC，返回32字节MAC"""
    mac = (c_uint8 * SM3_HMAC_SIZE)()
    gmssl.sm3_hmac_finish(byref(ctx), mac)
    return bytes(mac)


class Sm3Hmac:
    """SM3 HMAC 便捷类"""
    def __init__(self, key):
        self.ctx = sm3_hmac_init(key)

    def reset(self, key):
        gmssl.sm3_hmac_init(byref(self.ctx), key, c_size_t(len(key)))

    def update(self, data):
        sm3_hmac_update(self.ctx, data)

    def generate_mac(self):
        return sm3_hmac_finish(self.ctx)


# === SM3 KDF (密钥派生) ===

class SM3_KDF_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
        ("outlen", c_size_t),
    ]

def sm3_kdf_init(outlen):
    """初始化SM3 KDF"""
    ctx = SM3_KDF_CTX()
    gmssl.sm3_kdf_init(byref(ctx), c_size_t(outlen))
    return ctx

def sm3_kdf_update(ctx, data):
    """更新SM3 KDF输入"""
    gmssl.sm3_kdf_update(byref(ctx), data, c_size_t(len(data)))

def sm3_kdf_finish(ctx):
    """完成SM3 KDF，返回派生密钥"""
    out = create_string_buffer(ctx.outlen)
    gmssl.sm3_kdf_finish(byref(ctx), out)
    return out.raw


class Sm3Kdf:
    """SM3 KDF 便捷类"""
    def __init__(self, outlen):
        self.ctx = sm3_kdf_init(outlen)

    def update(self, data):
        sm3_kdf_update(self.ctx, data)

    def finish(self):
        return sm3_kdf_finish(self.ctx)


# === SM3 PBKDF2 ===

def sm3_pbkdf2(passwd, salt, iterator, keylen):
    """SM3 PBKDF2: 基于口令的密钥派生"""
    if len(salt) > SM3_PBKDF2_MAX_SALT_SIZE:
        raise ValueError(f"salt长度不能超过{SM3_PBKDF2_MAX_SALT_SIZE}字节")
    if iterator < SM3_PBKDF2_MIN_ITER or iterator > SM3_PBKDF2_MAX_ITER:
        raise ValueError(f"迭代次数必须在{SM3_PBKDF2_MIN_ITER}和{SM3_PBKDF2_MAX_ITER}之间")
    if isinstance(passwd, str):
        passwd = passwd.encode('utf-8')
    key = create_string_buffer(keylen)
    ret = gmssl.sm3_pbkdf2(
        c_char_p(passwd), c_size_t(len(passwd)),
        salt, c_size_t(len(salt)), c_size_t(iterator),
        c_size_t(keylen), key)
    _check(ret, "sm3_pbkdf2失败")
    return key.raw


# === SM3 DIGEST (通用摘要接口，支持带密钥) ===

class SM3_DIGEST_CTX(Structure):
    _fields_ = [
        ("sm3_ctx", SM3_CTX),
        ("state", c_int),
    ]

def sm3_digest_init():
    """初始化SM3摘要上下文"""
    ctx = SM3_DIGEST_CTX()
    ret = gmssl.sm3_digest_init(byref(ctx), c_char_p(0), c_size_t(0))
    _check(ret, "sm3_digest_init失败")
    return ctx

def sm3_digest_update(ctx, data):
    """更新SM3摘要数据"""
    ret = gmssl.sm3_digest_update(byref(ctx), data, c_size_t(len(data)))
    _check(ret, "sm3_digest_update失败")

def sm3_digest_finish(ctx):
    """完成SM3摘要"""
    dgst = (c_uint8 * SM3_DIGEST_SIZE)()
    ret = gmssl.sm3_digest_finish(byref(ctx), dgst)
    _check(ret, "sm3_digest_finish失败")
    return bytes(dgst)