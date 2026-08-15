# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# zuc.py - ZUC 祖冲之序列密码接口
# 封装 zuc.h 中定义的所有ZUC函数
# 包括: ZUC-128流密码、ZUC-128 MAC、128-EEA加密、128-EIA完整性
#       ZUC-256流密码、ZUC-256 MAC

from ctypes import *
from . import gmssl, _check
from .error import NativeError, StateError

# === 类型定义 ===
ZUC_BIT = c_uint32
ZUC_UINT5 = c_uint32
ZUC_UINT6 = c_uint8
ZUC_UINT15 = c_uint32
ZUC_UINT31 = c_uint32
ZUC_UINT32 = c_uint32

# === 常量 ===
ZUC_KEY_SIZE = 16
ZUC_IV_SIZE = 16
ZUC_MAC_SIZE = 4

ZUC256_KEY_SIZE = 32
ZUC256_IV_SIZE = 23
ZUC256_MAC32_SIZE = 4
ZUC256_MAC64_SIZE = 8
ZUC256_MAC128_SIZE = 16
ZUC256_MIN_MAC_SIZE = ZUC256_MAC32_SIZE
ZUC256_MAX_MAC_SIZE = ZUC256_MAC128_SIZE

# ========== ZUC-128 流密码 ==========

class ZUC_STATE(Structure):
    """ZUC-128/256 内部状态"""
    _fields_ = [
        ("LFSR", ZUC_UINT31 * 16),
        ("R1", ZUC_UINT32),
        ("R2", ZUC_UINT32),
    ]

class ZUC_CTX(Structure):
    """ZUC流密码加密上下文"""
    _fields_ = [
        ("zuc_state", ZUC_STATE),
        ("block", c_uint8 * 4),
        ("block_nbytes", c_size_t),
    ]

class ZUC_MAC_CTX(Structure):
    """ZUC-128 MAC上下文"""
    _fields_ = [
        ("LFSR", ZUC_UINT31 * 16),
        ("R1", ZUC_UINT32),
        ("R2", ZUC_UINT32),
        ("T", ZUC_UINT32),
        ("K0", ZUC_UINT32),
        ("buf", c_uint8 * 4),
        ("buflen", c_size_t),
    ]

class ZUC256_MAC_CTX(Structure):
    """ZUC-256 MAC上下文"""
    _fields_ = [
        ("LFSR", ZUC_UINT31 * 16),
        ("R1", ZUC_UINT32),
        ("R2", ZUC_UINT32),
        ("T", ZUC_UINT32 * 4),
        ("K0", ZUC_UINT32 * 4),
        ("buf", c_uint8 * 4),
        ("buflen", c_size_t),
        ("macbits", c_int),
    ]

# -- ZUC-128 基础函数 --
def zuc_init(state, key, iv):
    """初始化ZUC-128状态"""
    if len(key) != ZUC_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC_KEY_SIZE}字节")
    if len(iv) != ZUC_IV_SIZE:
        raise ValueError(f"IV长度必须为{ZUC_IV_SIZE}字节")
    gmssl.zuc_init(byref(state), (c_uint8 * ZUC_KEY_SIZE)(*key), (c_uint8 * ZUC_IV_SIZE)(*iv))

def zuc_generate_keystream(state, nwords):
    """生成ZUC-128密钥流（nwords个32位字）"""
    words = (ZUC_UINT32 * nwords)()
    gmssl.zuc_generate_keystream(byref(state), c_size_t(nwords), words)
    return bytes(words)

def zuc_generate_keyword(state):
    """生成单个ZUC-128密钥字"""
    return gmssl.zuc_generate_keyword(byref(state))

def zuc_encrypt(state, data):
    """ZUC-128直接加密（原地修改状态）"""
    out = create_string_buffer(len(data))
    gmssl.zuc_encrypt(byref(state), data, c_size_t(len(data)), out)
    return out.raw

# -- ZUC-128 MAC --
def zuc_mac_init(ctx, key, iv):
    """初始化ZUC-128 MAC"""
    if len(key) != ZUC_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC_KEY_SIZE}字节")
    if len(iv) != ZUC_IV_SIZE:
        raise ValueError(f"IV长度必须为{ZUC_IV_SIZE}字节")
    gmssl.zuc_mac_init(byref(ctx), (c_uint8 * ZUC_KEY_SIZE)(*key), (c_uint8 * ZUC_IV_SIZE)(*iv))

def zuc_mac_update(ctx, data):
    """更新ZUC-128 MAC"""
    gmssl.zuc_mac_update(byref(ctx), data, c_size_t(len(data)))

def zuc_mac_finish(ctx, data, nbits):
    """完成ZUC-128 MAC计算，返回4字节MAC"""
    mac = (c_uint8 * ZUC_MAC_SIZE)()
    gmssl.zuc_mac_finish(byref(ctx), data, c_size_t(nbits), mac)
    return bytes(mac)

# -- ZUC-128 EEA (加密算法) --
def zuc_eea_encrypt(input_words, nbits, key, count, bearer, direction):
    """ZUC-128 EEA加密: LTE加密算法"""
    if len(key) != ZUC_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC_KEY_SIZE}字节")
    nwords = (nbits + 31) // 32
    out_words = (ZUC_UINT32 * nwords)()
    in_arr = (ZUC_UINT32 * nwords)(*input_words)
    gmssl.zuc_eea_encrypt(
        in_arr, out_words, c_size_t(nbits),
        (c_uint8 * ZUC_KEY_SIZE)(*key),
        ZUC_UINT32(count), ZUC_UINT5(bearer), ZUC_BIT(direction))
    return list(out_words)

# -- ZUC-128 EIA (完整性算法) --
def zuc_eia_generate_mac(data_words, nbits, key, count, bearer, direction):
    """ZUC-128 EIA: 生成MAC（LTE完整性算法）"""
    if len(key) != ZUC_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC_KEY_SIZE}字节")
    nwords = (nbits + 31) // 32
    in_arr = (ZUC_UINT32 * nwords)(*data_words)
    return gmssl.zuc_eia_generate_mac(
        in_arr, c_size_t(nbits),
        (c_uint8 * ZUC_KEY_SIZE)(*key),
        ZUC_UINT32(count), ZUC_UINT5(bearer), ZUC_BIT(direction))

# -- ZUC-128 流式加密接口 --
def zuc_encrypt_init(ctx, key, iv):
    """初始化ZUC加密上下文"""
    if len(key) != ZUC_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC_KEY_SIZE}字节")
    if len(iv) != ZUC_IV_SIZE:
        raise ValueError(f"IV长度必须为{ZUC_IV_SIZE}字节")
    ret = gmssl.zuc_encrypt_init(byref(ctx), (c_uint8 * ZUC_KEY_SIZE)(*key), (c_uint8 * ZUC_IV_SIZE)(*iv))
    _check(ret, "zuc_encrypt_init失败")

def zuc_encrypt_update(ctx, data):
    """更新ZUC加密"""
    out = create_string_buffer(len(data) + 16)
    outlen = c_size_t()
    ret = gmssl.zuc_encrypt_update(byref(ctx), data, c_size_t(len(data)), out, byref(outlen))
    _check(ret, "zuc_encrypt_update失败")
    return out[:outlen.value]

def zuc_encrypt_finish(ctx):
    """完成ZUC加密"""
    out = create_string_buffer(16)
    outlen = c_size_t()
    ret = gmssl.zuc_encrypt_finish(byref(ctx), out, byref(outlen))
    _check(ret, "zuc_encrypt_finish失败")
    return out[:outlen.value]

# ========== ZUC-256 流密码 ==========

def zuc256_init(state, key, iv):
    """初始化ZUC-256状态"""
    if len(key) != ZUC256_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC256_KEY_SIZE}字节")
    if len(iv) != ZUC256_IV_SIZE:
        raise ValueError(f"IV长度必须为{ZUC256_IV_SIZE}字节")
    gmssl.zuc256_init(byref(state), (c_uint8 * ZUC256_KEY_SIZE)(*key), (c_uint8 * ZUC256_IV_SIZE)(*iv))

def zuc256_generate_keystream(state, nwords):
    """生成ZUC-256密钥流（nwords个32位字）"""
    words = (ZUC_UINT32 * nwords)()
    gmssl.zuc256_generate_keystream(byref(state), c_size_t(nwords), words)
    return bytes(words)

def zuc256_generate_keyword(state):
    """生成单个ZUC-256密钥字"""
    return gmssl.zuc256_generate_keyword(byref(state))

# -- ZUC-256 MAC --
def zuc256_mac_init(ctx, key, iv, macbits):
    """初始化ZUC-256 MAC (macbits=32/64/128)"""
    if len(key) != ZUC256_KEY_SIZE:
        raise ValueError(f"密钥长度必须为{ZUC256_KEY_SIZE}字节")
    if len(iv) != ZUC256_IV_SIZE:
        raise ValueError(f"IV长度必须为{ZUC256_IV_SIZE}字节")
    gmssl.zuc256_mac_init(
        byref(ctx), (c_uint8 * ZUC256_KEY_SIZE)(*key),
        (c_uint8 * ZUC256_IV_SIZE)(*iv), c_int(macbits))

def zuc256_mac_update(ctx, data):
    """更新ZUC-256 MAC"""
    gmssl.zuc256_mac_update(byref(ctx), data, c_size_t(len(data)))

def zuc256_mac_finish(ctx, data, nbits, mac_size):
    """完成ZUC-256 MAC计算"""
    mac = create_string_buffer(mac_size)
    gmssl.zuc256_mac_finish(byref(ctx), data, c_size_t(nbits), mac)
    return mac.raw


# ========== 便捷封装类 ==========

class Zuc:
    """ZUC-128 流密码加密/解密类"""
    def __init__(self, key, iv):
        self.ctx = ZUC_CTX()
        zuc_encrypt_init(self.ctx, key, iv)

    def update(self, data):
        return zuc_encrypt_update(self.ctx, data)

    def finish(self):
        return zuc_encrypt_finish(self.ctx)


class ZucMac:
    """ZUC-128 MAC 计算类"""
    def __init__(self, key, iv):
        self.ctx = ZUC_MAC_CTX()
        zuc_mac_init(self.ctx, key, iv)

    def update(self, data):
        zuc_mac_update(self.ctx, data)

    def finish(self, data, nbits):
        return zuc_mac_finish(self.ctx, data, nbits)


class Zuc256Mac:
    """ZUC-256 MAC 计算类"""
    def __init__(self, key, iv, macbits=32):
        self.ctx = ZUC256_MAC_CTX()
        zuc256_mac_init(self.ctx, key, iv, macbits)

    def update(self, data):
        zuc256_mac_update(self.ctx, data)

    def finish(self, data, nbits, mac_size=None):
        if mac_size is None:
            mac_size = (self.ctx.macbits + 7) // 8
        return zuc256_mac_finish(self.ctx, data, nbits, mac_size)