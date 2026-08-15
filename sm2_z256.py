# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm2_z256.py - SM2 Z256 低层数学接口
# 封装 sm2_z256.h 中定义的所有大整数和椭圆曲线运算

from ctypes import *
from . import gmssl, _check

# === 类型定义 ===
# sm2_z256_t = uint64_t[4]
# sm2_z512_t = uint64_t[8]

# === SM2 Z256 基础运算 ===

def sm2_z256_set_one():
    """返回全1的z256值"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_set_one(r)
    return r

def sm2_z256_set_zero():
    """返回全0的z256值"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_set_zero(r)
    return r

def sm2_z256_rand_range(range_val):
    """生成[0, range)范围内的随机z256"""
    r = (c_uint64 * 4)()
    ret = gmssl.sm2_z256_rand_range(r, range_val)
    _check(ret, "sm2_z256_rand_range失败")
    return r

def sm2_z256_copy(a):
    """复制z256值"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_copy(r, a)
    return r

def sm2_z256_copy_conditional(dst, src, move):
    """条件复制"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_copy_conditional(r, src, c_uint64(move))
    return r

def sm2_z256_from_bytes(data):
    """从32字节大端序数据转换为z256"""
    if len(data) != 32:
        raise ValueError(f"需要32字节，实际{len(data)}字节")
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_from_bytes(r, (c_uint8 * 32)(*data))
    return r

def sm2_z256_to_bytes(a):
    """将z256转换为32字节大端序数据"""
    out = (c_uint8 * 32)()
    gmssl.sm2_z256_to_bytes(a, out)
    return bytes(out)

def sm2_z256_cmp(a, b):
    """比较两个z256值"""
    return gmssl.sm2_z256_cmp(a, b)

def sm2_z256_is_zero(a):
    """判断是否为0"""
    return gmssl.sm2_z256_is_zero(a) != 0

def sm2_z256_equ(a, b):
    """判断两值是否相等"""
    return gmssl.sm2_z256_equ(a, b) != 0

def sm2_z256_rshift(a, nbits):
    """右移nbits位"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_rshift(r, a, c_uint(nbits))
    return r

def sm2_z256_add(a, b):
    """加法，返回进位"""
    r = (c_uint64 * 4)()
    carry = gmssl.sm2_z256_add(r, a, b)
    return r, carry

def sm2_z256_sub(a, b):
    """减法，返回借位"""
    r = (c_uint64 * 4)()
    borrow = gmssl.sm2_z256_sub(r, a, b)
    return r, borrow

def sm2_z256_mul(a, b):
    """乘法 r[8] = a * b"""
    r = (c_uint64 * 8)()
    gmssl.sm2_z256_mul(r, a, b)
    return r

def sm2_z256_get_booth(a, window_size, i):
    """获取Booth编码值"""
    return gmssl.sm2_z256_get_booth(a, c_uint(window_size), c_int(i))

def sm2_z256_from_hex(hex_str):
    """从十六进制字符串转换为z256"""
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_from_hex(r, hex_str.encode('ascii'))
    return r

def sm2_z256_equ_hex(a, hex_str):
    """判断z256值是否等于十六进制字符串表示的值"""
    return gmssl.sm2_z256_equ_hex(a, hex_str.encode('ascii'))

# === Fp 模p运算 ===

def sm2_z256_modp_add(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_add(r, a, b)
    return r

def sm2_z256_modp_dbl(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_dbl(r, a)
    return r

def sm2_z256_modp_tri(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_tri(r, a)
    return r

def sm2_z256_modp_sub(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_sub(r, a, b)
    return r

def sm2_z256_modp_neg(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_neg(r, a)
    return r

def sm2_z256_modp_haf(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_haf(r, a)
    return r

def sm2_z256_modp_to_mont(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_to_mont(a, r)
    return r

def sm2_z256_modp_from_mont(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_from_mont(r, a)
    return r

def sm2_z256_modp_mont_mul(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_mont_mul(r, a, b)
    return r

def sm2_z256_modp_mont_sqr(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_mont_sqr(r, a)
    return r

def sm2_z256_modp_mont_exp(a, e):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_mont_exp(r, a, e)
    return r

def sm2_z256_modp_mont_inv(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modp_mont_inv(r, a)
    return r

def sm2_z256_modp_mont_sqrt(a):
    r = (c_uint64 * 4)()
    ret = gmssl.sm2_z256_modp_mont_sqrt(r, a)
    _check(ret, "sm2_z256_modp_mont_sqrt失败")
    return r

# === Fn 模n运算 ===

def sm2_z256_modn_add(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_add(r, a, b)
    return r

def sm2_z256_modn_sub(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_sub(r, a, b)
    return r

def sm2_z256_modn_neg(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_neg(r, a)
    return r

def sm2_z256_modn_mul(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_mul(r, a, b)
    return r

def sm2_z256_modn_sqr(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_sqr(r, a)
    return r

def sm2_z256_modn_exp(a, e):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_exp(r, a, e)
    return r

def sm2_z256_modn_inv(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_inv(r, a)
    return r

def sm2_z256_modn_to_mont(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_to_mont(a, r)
    return r

def sm2_z256_modn_from_mont(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_from_mont(r, a)
    return r

def sm2_z256_modn_mont_mul(a, b):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_mont_mul(r, a, b)
    return r

def sm2_z256_modn_mont_sqr(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_mont_sqr(r, a)
    return r

def sm2_z256_modn_mont_exp(a, e):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_mont_exp(r, a, e)
    return r

def sm2_z256_modn_mont_inv(a):
    r = (c_uint64 * 4)()
    gmssl.sm2_z256_modn_mont_inv(r, a)
    return r

# === SM2 椭圆曲线点 (Jacobian坐标) ===

class SM2_Z256_POINT(Structure):
    _fields_ = [
        ("X", c_uint64 * 4),
        ("Y", c_uint64 * 4),
        ("Z", c_uint64 * 4),
    ]

class SM2_Z256_AFFINE_POINT(Structure):
    _fields_ = [
        ("x", c_uint64 * 4),
        ("y", c_uint64 * 4),
    ]

def sm2_z256_point_set_infinity():
    """获取无穷远点"""
    P = SM2_Z256_POINT()
    gmssl.sm2_z256_point_set_infinity(byref(P))
    return P

def sm2_z256_point_is_at_infinity(P):
    """判断是否为无穷远点"""
    return gmssl.sm2_z256_point_is_at_infinity(byref(P))

def sm2_z256_point_to_bytes(P):
    """G1点转64字节(X||Y)"""
    out = (c_uint8 * 64)()
    ret = gmssl.sm2_z256_point_to_bytes(byref(P), out)
    _check(ret, "sm2_z256_point_to_bytes失败")
    return bytes(out)

def sm2_z256_point_from_bytes(data):
    """从64字节(X||Y)构造G1点"""
    if len(data) != 64:
        raise ValueError(f"需要64字节，实际{len(data)}字节")
    P = SM2_Z256_POINT()
    ret = gmssl.sm2_z256_point_from_bytes(byref(P), (c_uint8 * 64)(*data))
    _check(ret, "sm2_z256_point_from_bytes失败")
    return P

def sm2_z256_point_from_hex(hex_str):
    """从十六进制字符串构造G1点"""
    P = SM2_Z256_POINT()
    ret = gmssl.sm2_z256_point_from_hex(byref(P), hex_str.encode('ascii'))
    _check(ret, "sm2_z256_point_from_hex失败")
    return P

def sm2_z256_point_equ_hex(P, hex_str):
    return gmssl.sm2_z256_point_equ_hex(byref(P), hex_str.encode('ascii'))

def sm2_z256_point_is_on_curve(P):
    """判断点是否在SM2曲线上"""
    return gmssl.sm2_z256_point_is_on_curve(byref(P))

def sm2_z256_point_equ(P, Q):
    """判断两个Jacobian点是否等价"""
    return gmssl.sm2_z256_point_equ(byref(P), byref(Q))

def sm2_z256_point_get_xy(P):
    """获取点的仿射坐标"""
    x = (c_uint64 * 4)()
    y = (c_uint64 * 4)()
    ret = gmssl.sm2_z256_point_get_xy(byref(P), x, y)
    _check(ret, "sm2_z256_point_get_xy失败")
    return x, y

def sm2_z256_point_dbl(P):
    """倍点 R = 2P"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_dbl(byref(R), byref(P))
    return R

def sm2_z256_point_add(P, Q):
    """点加法 R = P + Q"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_add(byref(R), byref(P), byref(Q))
    return R

def sm2_z256_point_neg(P):
    """点取负 R = -P"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_neg(byref(R), byref(P))
    return R

def sm2_z256_point_sub(P, Q):
    """点减法 R = P - Q"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_sub(byref(R), byref(P), byref(Q))
    return R

def sm2_z256_point_get_affine(P):
    """Jacobian点转仿射坐标（通过 get_xy 实现，DLL未导出 get_affine）"""
    x, y = sm2_z256_point_get_xy(P)
    return x, y

# -- 仿射点运算 --
def sm2_z256_point_copy_affine(P_affine):
    """仿射点复制为Jacobian点"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_copy_affine(byref(R), byref(P_affine))
    return R

def sm2_z256_point_add_affine(P, Q_affine):
    """Jacobian点 + 仿射点"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_add_affine(byref(R), byref(P), byref(Q_affine))
    return R

def sm2_z256_point_sub_affine(P, Q_affine):
    """Jacobian点 - 仿射点"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_sub_affine(byref(R), byref(P), byref(Q_affine))
    return R

# -- 标量乘 --
def sm2_z256_point_mul_generator(k):
    """生成元标量乘 R = k * G"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_mul_generator(byref(R), k)
    return R

def sm2_z256_point_mul_pre_compute(P):
    """预计算点表 P, 2P, ..., 16P"""
    T = (SM2_Z256_POINT * 16)()
    gmssl.sm2_z256_point_mul_pre_compute(byref(P), T)
    return T

def sm2_z256_point_mul_ex(k, P_table):
    """使用预计算表加速标量乘"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_mul_ex(byref(R), k, P_table)
    return R

def sm2_z256_point_mul(k, P):
    """标量乘 R = k * P"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_mul(byref(R), k, byref(P))
    return R

def sm2_z256_point_mul_sum(t, P, s):
    """R = t * P + s * G"""
    R = SM2_Z256_POINT()
    gmssl.sm2_z256_point_mul_sum(byref(R), t, byref(P), s)
    return R

# === 常量 ===
def sm2_z256_prime():
    """获取SM2素数p"""
    gmssl.sm2_z256_prime.restype = POINTER(c_uint64 * 4)
    return gmssl.sm2_z256_prime().contents

def sm2_z256_order():
    """获取SM2阶n"""
    gmssl.sm2_z256_order.restype = POINTER(c_uint64 * 4)
    return gmssl.sm2_z256_order().contents

def sm2_z256_order_minus_one():
    """获取 n-1"""
    gmssl.sm2_z256_order_minus_one.restype = POINTER(c_uint64 * 4)
    return gmssl.sm2_z256_order_minus_one().contents

def sm2_z256_one():
    """获取SM2的1值"""
    gmssl.sm2_z256_one.restype = POINTER(c_uint64 * 4)
    return gmssl.sm2_z256_one().contents

# === 点编码 ===
def sm2_z256_point_from_x_bytes(x_bytes, y_is_odd):
    """从x坐标和y奇偶性构造点"""
    if len(x_bytes) != 32:
        raise ValueError(f"需要32字节，实际{len(x_bytes)}字节")
    P = SM2_Z256_POINT()
    ret = gmssl.sm2_z256_point_from_x_bytes(byref(P), (c_uint8 * 32)(*x_bytes), c_int(y_is_odd))
    _check(ret, "sm2_z256_point_from_x_bytes失败")
    return P

def sm2_z256_point_from_hash(data, y_is_odd):
    """从哈希值构造点(Hash-to-Point)"""
    P = SM2_Z256_POINT()
    ret = gmssl.sm2_z256_point_from_hash(byref(P), data, c_size_t(len(data)), c_int(y_is_odd))
    _check(ret, "sm2_z256_point_from_hash失败")
    return P

def sm2_z256_point_from_octets(data):
    """从压缩/非压缩字节串构造点"""
    P = SM2_Z256_POINT()
    ret = gmssl.sm2_z256_point_from_octets(byref(P), data, c_size_t(len(data)))
    _check(ret, "sm2_z256_point_from_octets失败")
    return P

def sm2_z256_point_to_uncompressed_octets(P):
    """点转非压缩字节串(65字节: 0x04||X||Y)"""
    out = (c_uint8 * 65)()
    ret = gmssl.sm2_z256_point_to_uncompressed_octets(byref(P), out)
    _check(ret, "sm2_z256_point_to_uncompressed_octets失败")
    return bytes(out)

def sm2_z256_point_to_compressed_octets(P):
    """点转压缩字节串(33字节)"""
    out = (c_uint8 * 33)()
    ret = gmssl.sm2_z256_point_to_compressed_octets(byref(P), out)
    _check(ret, "sm2_z256_point_to_compressed_octets失败")
    return bytes(out)

def sm2_z256_point_to_der(P):
    """点 DER 编码"""
    out_ptr = c_void_p()
    outlen = c_size_t()
    ret = gmssl.sm2_z256_point_to_der(byref(P), byref(out_ptr), byref(outlen))
    _check(ret, "sm2_z256_point_to_der失败")
    from . import libc
    der = create_string_buffer(outlen.value)
    libc.memcpy(der, out_ptr, outlen)
    libc.free(out_ptr)
    return der.raw

def sm2_z256_point_from_der(data):
    """从 DER 解码点"""
    P = SM2_Z256_POINT()
    in_ptr = c_char_p(data)
    inlen = c_size_t(len(data))
    ret = gmssl.sm2_z256_point_from_der(byref(P), byref(in_ptr), byref(inlen))
    _check(ret, "sm2_z256_point_from_der失败")
    return P