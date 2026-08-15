# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# sm9_z256.py - SM9 Z256 低层数学接口
# 封装 sm9_z256.h 中定义的所有有限域运算函数
# 包括: Z256大整数、Fp、Fp2、Fp4、Fp12、椭圆曲线点、扭曲点、配对运算

from ctypes import *
from . import gmssl, _check

# === 类型定义 ===
# sm9_z256_t = uint64_t[4]
# 注意: 在ctypes中，数组参数可以直接传 c_uint64 * 4

SM9_Z256_SIZE = 32  # bytes

# === Z256 基础运算 (sm9_z256_t) ===

def z256_set_one():
    """返回全1的z256值"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_set_one(r)
    return r

def z256_set_zero():
    """返回全0的z256值"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_set_zero(r)
    return r

def z256_copy(a):
    """复制z256值 r = a"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_copy(r, a)
    return r

def z256_copy_conditional(a, move):
    """条件复制：move非0时复制，否则不复制"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_copy_conditional(r, a, c_uint64(move))
    return r

def z256_cmp(a, b):
    """比较两个z256值: a<b返回-1, a==b返回0, a>b返回1"""
    return gmssl.sm9_z256_cmp(a, b)

def z256_is_zero(a):
    """判断是否为0"""
    return gmssl.sm9_z256_is_zero(a) != 0

def z256_equ(a, b):
    """判断两值是否相等"""
    return gmssl.sm9_z256_equ(a, b) != 0

def z256_add(a, b):
    """加法 r = a + b, 返回进位"""
    r = (c_uint64 * 4)()
    carry = gmssl.sm9_z256_add(r, a, b)
    return r, carry

def z256_sub(a, b):
    """减法 r = a - b, 返回借位"""
    r = (c_uint64 * 4)()
    borrow = gmssl.sm9_z256_sub(r, a, b)
    return r, borrow

def z256_mul(a, b):
    """乘法 r[8] = a * b"""
    r = (c_uint64 * 8)()
    gmssl.sm9_z256_mul(r, a, b)
    return r

def z256_from_bytes(data):
    """从32字节大端序数据转换为z256"""
    if len(data) != 32:
        raise ValueError(f"需要32字节，实际{len(data)}字节")
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_from_bytes(r, (c_uint8 * 32)(*data))
    return r

def z256_to_bytes(a):
    """将z256转换为32字节大端序数据"""
    out = (c_uint8 * 32)()
    gmssl.sm9_z256_to_bytes(a, out)
    return bytes(out)

def z256_from_hex(hex_str):
    """从十六进制字符串转换为z256"""
    r = (c_uint64 * 4)()
    ret = gmssl.sm9_z256_from_hex(r, hex_str.encode('ascii'))
    _check(ret, "sm9_z256_from_hex失败")
    return r

def z256_to_hex(a):
    """将z256转换为十六进制字符串"""
    buf = create_string_buffer(64)
    gmssl.sm9_z256_to_hex(a, buf)
    return buf.value.decode('ascii')

def z256_equ_hex(a, hex_str):
    """判断z256值是否等于十六进制字符串表示的值"""
    return gmssl.sm9_z256_equ_hex(a, hex_str.encode('ascii')) != 0

def z256_to_bits(a):
    """将z256转换为256位二进制字符串"""
    buf = create_string_buffer(256)
    gmssl.sm9_z256_to_bits(a, buf)
    return buf.value.decode('ascii')

def z256_rand_range(range_val):
    """生成[0, range)范围内的随机z256"""
    r = (c_uint64 * 4)()
    ret = gmssl.sm9_z256_rand_range(r, range_val)
    _check(ret, "sm9_z256_rand_range失败")
    return r

def z256_print_bn(prefix, a):
    """打印z256值（调试用）"""
    gmssl.sm9_z256_print_bn(prefix.encode('ascii'), a)

def z256_prime():
    """获取SM9素数p（硬编码，该函数未从DLL导出）"""
    # SM9 BN曲线素数 p = 0xB6400000...351457D
    return z256_from_hex("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D")

# === Fp 模p运算 ===

def z256_modp_add(a, b):
    """模p加法 r = (a + b) mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_add(r, a, b)
    return r

def z256_modp_sub(a, b):
    """模p减法 r = (a - b) mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_sub(r, a, b)
    return r

def z256_modp_dbl(a):
    """模p倍乘 r = 2a mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_dbl(r, a)
    return r

def z256_modp_tri(a):
    """模p三倍 r = 3a mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_tri(r, a)
    return r

def z256_modp_haf(a):
    """模p减半 r = a/2 mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_haf(r, a)
    return r

def z256_modp_neg(a):
    """模p取负 r = -a mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_neg(r, a)
    return r

def z256_modp_to_mont(a):
    """转换为Montgomery域表示"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_to_mont(r, a)
    return r

def z256_modp_from_mont(a):
    """从Montgomery域转换回普通表示"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_from_mont(r, a)
    return r

def z256_modp_mont_mul(a, b):
    """Montgomery域乘法 r = a * b * R^{-1} mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_mont_mul(r, a, b)
    return r

def z256_modp_mont_sqr(a):
    """Montgomery域平方 r = a^2 * R^{-1} mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_mont_sqr(r, a)
    return r

def z256_modp_mont_pow(a, e):
    """Montgomery域幂运算 r = a^e * R^{-(e-1)} mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_mont_pow(r, a, e)
    return r

def z256_modp_mont_inv(a):
    """Montgomery域求逆 r = a^{-1} * R mod p"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modp_mont_inv(r, a)
    return r

# === Fn 模n运算 (群阶) ===

def z256_order():
    """获取SM9群阶n"""
    gmssl.sm9_z256_order.restype = POINTER(c_uint64 * 4)
    ptr = gmssl.sm9_z256_order()
    return ptr.contents

def z256_modn_add(a, b):
    """模n加法"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_add(r, a, b)
    return r

def z256_modn_sub(a, b):
    """模n减法"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_sub(r, a, b)
    return r

def z256_modn_mul(a, b):
    """模n乘法"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_mul(r, a, b)
    return r

def z256_modn_pow(a, e):
    """模n幂运算"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_pow(r, a, e)
    return r

def z256_modn_inv(a):
    """模n求逆"""
    r = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_inv(r, a)
    return r

def z256_modn_from_hash(Ha):
    """从40字节哈希值转换为模n的整数"""
    if len(Ha) != 40:
        raise ValueError(f"需要40字节，实际{len(Ha)}字节")
    h = (c_uint64 * 4)()
    gmssl.sm9_z256_modn_from_hash(h, (c_uint8 * 40)(*Ha))
    return h

# === Fp2 二次扩域运算 ===
# sm9_z256_fp2_t = sm9_z256_t[2] = uint64_t[2][4]

Fp2 = c_uint64 * 8  # 2 * 4 = 8个uint64

def fp2_set_one():
    """Fp2单位元"""
    r = Fp2()
    gmssl.sm9_z256_fp2_set_one(r)
    return r

def fp2_set_zero():
    """Fp2零元"""
    r = Fp2()
    gmssl.sm9_z256_fp2_set_zero(r)
    return r

def fp2_is_one(a):
    """判断是否为Fp2单位元"""
    return gmssl.sm9_z256_fp2_is_one(a)

def fp2_is_zero(a):
    """判断是否为Fp2零元"""
    return gmssl.sm9_z256_fp2_is_zero(a)

def fp2_equ(a, b):
    """判断Fp2两元素相等"""
    return gmssl.sm9_z256_fp2_equ(a, b)

def fp2_copy(a):
    """复制Fp2元素"""
    r = Fp2()
    gmssl.sm9_z256_fp2_copy(r, a)
    return r

def fp2_rand():
    """生成随机Fp2元素"""
    r = Fp2()
    ret = gmssl.sm9_z256_fp2_rand(r)
    _check(ret, "sm9_z256_fp2_rand失败")
    return r

def fp2_to_bytes(a):
    """Fp2转64字节"""
    buf = (c_uint8 * 64)()
    gmssl.sm9_z256_fp2_to_bytes(a, buf)
    return bytes(buf)

def fp2_from_bytes(data):
    """从64字节转Fp2"""
    if len(data) != 64:
        raise ValueError(f"需要64字节，实际{len(data)}字节")
    r = Fp2()
    ret = gmssl.sm9_z256_fp2_from_bytes(r, (c_uint8 * 64)(*data))
    _check(ret, "sm9_z256_fp2_from_bytes失败")
    return r

def fp2_to_hex(a):
    """Fp2转十六进制字符串(129字符)"""
    buf = create_string_buffer(129)
    gmssl.sm9_z256_fp2_to_hex(a, buf)
    return buf.value.decode('ascii')

def fp2_from_hex(hex_str):
    """从十六进制字符串(129字符)转Fp2"""
    r = Fp2()
    ret = gmssl.sm9_z256_fp2_from_hex(r, hex_str.encode('ascii'))
    _check(ret, "sm9_z256_fp2_from_hex失败")
    return r

def fp2_add(a, b):
    """Fp2加法"""
    r = Fp2()
    gmssl.sm9_z256_fp2_add(r, a, b)
    return r

def fp2_dbl(a):
    """Fp2倍乘"""
    r = Fp2()
    gmssl.sm9_z256_fp2_dbl(r, a)
    return r

def fp2_tri(a):
    """Fp2三倍"""
    r = Fp2()
    gmssl.sm9_z256_fp2_tri(r, a)
    return r

def fp2_sub(a, b):
    """Fp2减法"""
    r = Fp2()
    gmssl.sm9_z256_fp2_sub(r, a, b)
    return r

def fp2_neg(a):
    """Fp2取负"""
    r = Fp2()
    gmssl.sm9_z256_fp2_neg(r, a)
    return r

def fp2_a_mul_u(a):
    """Fp2乘u (a * u)"""
    r = Fp2()
    gmssl.sm9_z256_fp2_a_mul_u(r, a)
    return r

def fp2_mul(a, b):
    """Fp2乘法"""
    r = Fp2()
    gmssl.sm9_z256_fp2_mul(r, a, b)
    return r

def fp2_mul_u(a, b):
    """Fp2乘法 by u"""
    r = Fp2()
    gmssl.sm9_z256_fp2_mul_u(r, a, b)
    return r

def fp2_mul_fp(a, k):
    """Fp2乘Fp标量"""
    r = Fp2()
    gmssl.sm9_z256_fp2_mul_fp(r, a, k)
    return r

def fp2_sqr(a):
    """Fp2平方"""
    r = Fp2()
    gmssl.sm9_z256_fp2_sqr(r, a)
    return r

def fp2_sqr_u(a):
    """Fp2平方 by u"""
    r = Fp2()
    gmssl.sm9_z256_fp2_sqr_u(r, a)
    return r

def fp2_inv(a):
    """Fp2求逆"""
    r = Fp2()
    gmssl.sm9_z256_fp2_inv(r, a)
    return r

def fp2_div(a, b):
    """Fp2除法 r = a / b"""
    r = Fp2()
    gmssl.sm9_z256_fp2_div(r, a, b)
    return r

def fp2_haf(a):
    """Fp2减半"""
    r = Fp2()
    gmssl.sm9_z256_fp2_haf(r, a)
    return r

def fp2_conjugate(a):
    """Fp2共轭"""
    r = Fp2()
    gmssl.sm9_z256_fp2_conjugate(r, a)
    return r

def fp2_frobenius(a):
    """Fp2 Frobenius映射"""
    r = Fp2()
    gmssl.sm9_z256_fp2_frobenius(r, a)
    return r

# === Fp4 四次扩域 ===
# sm9_z256_fp4_t = sm9_z256_fp2_t[2]

Fp4 = c_uint64 * 16  # 2 * 2 * 4 = 16

def fp4_is_zero(a):
    return gmssl.sm9_z256_fp4_is_zero(a)

def fp4_equ(a, b):
    return gmssl.sm9_z256_fp4_equ(a, b)

def fp4_rand():
    r = Fp4()
    ret = gmssl.sm9_z256_fp4_rand(r)
    _check(ret, "sm9_z256_fp4_rand失败")
    return r

def fp4_copy(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_copy(r, a)
    return r

def fp4_to_bytes(a):
    buf = (c_uint8 * 128)()
    gmssl.sm9_z256_fp4_to_bytes(a, buf)
    return bytes(buf)

def fp4_from_bytes(data):
    if len(data) != 128:
        raise ValueError(f"需要128字节，实际{len(data)}字节")
    r = Fp4()
    ret = gmssl.sm9_z256_fp4_from_bytes(r, (c_uint8 * 128)(*data))
    _check(ret, "sm9_z256_fp4_from_bytes失败")
    return r

def fp4_from_hex(hex_str):
    r = Fp4()
    ret = gmssl.sm9_z256_fp4_from_hex(r, hex_str.encode('ascii'))
    _check(ret, "sm9_z256_fp4_from_hex失败")
    return r

def fp4_to_hex(a):
    buf = create_string_buffer(259)
    gmssl.sm9_z256_fp4_to_hex(a, buf)
    return buf.value.decode('ascii')

def fp4_add(a, b):
    r = Fp4()
    gmssl.sm9_z256_fp4_add(r, a, b)
    return r

def fp4_dbl(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_dbl(r, a)
    return r

def fp4_sub(a, b):
    r = Fp4()
    gmssl.sm9_z256_fp4_sub(r, a, b)
    return r

def fp4_neg(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_neg(r, a)
    return r

def fp4_haf(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_haf(r, a)
    return r

def fp4_a_mul_v(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_a_mul_v(r, a)
    return r

def fp4_mul(a, b):
    r = Fp4()
    gmssl.sm9_z256_fp4_mul(r, a, b)
    return r

def fp4_mul_fp(a, k):
    r = Fp4()
    gmssl.sm9_z256_fp4_mul_fp(r, a, k)
    return r

def fp4_mul_fp2(a, b0):
    r = Fp4()
    gmssl.sm9_z256_fp4_mul_fp2(r, a, b0)
    return r

def fp4_mul_v(a, b):
    r = Fp4()
    gmssl.sm9_z256_fp4_mul_v(r, a, b)
    return r

def fp4_sqr(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_sqr(r, a)
    return r

def fp4_sqr_v(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_sqr_v(r, a)
    return r

def fp4_inv(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_inv(r, a)
    return r

def fp4_frobenius(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_frobenius(r, a)
    return r

def fp4_conjugate(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_conjugate(r, a)
    return r

def fp4_frobenius2(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_frobenius2(r, a)
    return r

def fp4_frobenius3(a):
    r = Fp4()
    gmssl.sm9_z256_fp4_frobenius3(r, a)
    return r

# === Fp12 十二次扩域 ===
# sm9_z256_fp12_t = sm9_z256_fp4_t[3]

Fp12 = c_uint64 * 48  # 3 * 4 * 4 = 48

def fp12_set_one():
    r = Fp12()
    gmssl.sm9_z256_fp12_set_one(r)
    return r

def fp12_set_zero():
    r = Fp12()
    gmssl.sm9_z256_fp12_set_zero(r)
    return r

def fp12_copy(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_copy(r, a)
    return r

def fp12_rand():
    r = Fp12()
    ret = gmssl.sm9_z256_fp12_rand(r)
    _check(ret, "sm9_z256_fp12_rand失败")
    return r

def fp12_from_hex(hex_str):
    r = Fp12()
    ret = gmssl.sm9_z256_fp12_from_hex(r, hex_str.encode('ascii'))
    _check(ret, "sm9_z256_fp12_from_hex失败")
    return r

def fp12_to_hex(a):
    buf = create_string_buffer(779)
    gmssl.sm9_z256_fp12_to_hex(a, buf)
    return buf.value.decode('ascii')

def fp12_to_bytes(a):
    buf = (c_uint8 * 384)()
    gmssl.sm9_z256_fp12_to_bytes(a, buf)
    return bytes(buf)

def fp12_from_bytes(data):
    if len(data) != 384:
        raise ValueError(f"需要384字节，实际{len(data)}字节")
    r = Fp12()
    ret = gmssl.sm9_z256_fp12_from_bytes(r, (c_uint8 * 384)(*data))
    _check(ret, "sm9_z256_fp12_from_bytes失败")
    return r

def fp12_print_bn(prefix, a):
    gmssl.sm9_z256_fp12_print(prefix.encode('ascii'), a)

def fp12_set(a0, a1, a2):
    """从三个Fp4元素构造Fp12"""
    r = Fp12()
    gmssl.sm9_z256_fp12_set(r, a0, a1, a2)
    return r

def fp12_equ(a, b):
    return gmssl.sm9_z256_fp12_equ(a, b)

def fp12_add(a, b):
    r = Fp12()
    gmssl.sm9_z256_fp12_add(r, a, b)
    return r

def fp12_dbl(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_dbl(r, a)
    return r

def fp12_tri(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_tri(r, a)
    return r

def fp12_sub(a, b):
    r = Fp12()
    gmssl.sm9_z256_fp12_sub(r, a, b)
    return r

def fp12_neg(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_neg(r, a)
    return r

def fp12_mul(a, b):
    r = Fp12()
    gmssl.sm9_z256_fp12_mul(r, a, b)
    return r

def fp12_sqr(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_sqr(r, a)
    return r

def fp12_inv(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_inv(r, a)
    return r

def fp12_pow(a, k):
    r = Fp12()
    gmssl.sm9_z256_fp12_pow(r, a, k)
    return r

def fp12_frobenius(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_frobenius(r, a)
    return r

def fp12_frobenius2(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_frobenius2(r, a)
    return r

def fp12_frobenius3(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_frobenius3(r, a)
    return r

def fp12_frobenius6(a):
    r = Fp12()
    gmssl.sm9_z256_fp12_frobenius6(r, a)
    return r

# === E(F_p) 椭圆曲线点 (G1群) ===
# SM9_Z256_POINT: { X, Y, Z } 各为 sm9_z256_t

class Sm9Point(Structure):
    _fields_ = [
        ("X", c_uint64 * 4),
        ("Y", c_uint64 * 4),
        ("Z", c_uint64 * 4),
    ]

def z256_generator():
    """获取G1群生成元P1"""
    gmssl.sm9_z256_generator.restype = POINTER(Sm9Point)
    ptr = gmssl.sm9_z256_generator()
    return ptr.contents

def z256_point_from_hex(hex_str):
    """从十六进制字符串构造G1点"""
    R = Sm9Point()
    ret = gmssl.sm9_z256_point_from_hex(byref(R), hex_str.encode('ascii'))
    _check(ret, "sm9_z256_point_from_hex失败")
    return R

def z256_point_is_at_infinity(P):
    """判断G1点是否为无穷远点"""
    return gmssl.sm9_z256_point_is_at_infinity(byref(P))

def z256_point_set_infinity():
    """返回G1群无穷远点"""
    R = Sm9Point()
    gmssl.sm9_z256_point_set_infinity(byref(R))
    return R

def z256_point_get_xy(P):
    """获取G1点的仿射坐标(X, Y)"""
    x = (c_uint64 * 4)()
    y = (c_uint64 * 4)()
    gmssl.sm9_z256_point_get_xy(byref(P), x, y)
    return x, y

def z256_point_equ(P, Q):
    """判断两个G1点是否相等"""
    return gmssl.sm9_z256_point_equ(byref(P), byref(Q))

def z256_point_is_on_curve(P):
    """判断G1点是否在曲线上"""
    return gmssl.sm9_z256_point_is_on_curve(byref(P))

def z256_point_dbl(P):
    """G1点倍点 R = 2P"""
    R = Sm9Point()
    gmssl.sm9_z256_point_dbl(byref(R), byref(P))
    return R

def z256_point_neg(P):
    """G1点取负 R = -P"""
    R = Sm9Point()
    gmssl.sm9_z256_point_neg(byref(R), byref(P))
    return R

def z256_point_add(P, Q):
    """G1点加法 R = P + Q"""
    R = Sm9Point()
    gmssl.sm9_z256_point_add(byref(R), byref(P), byref(Q))
    return R

def z256_point_sub(P, Q):
    """G1点减法 R = P - Q"""
    R = Sm9Point()
    gmssl.sm9_z256_point_sub(byref(R), byref(P), byref(Q))
    return R

def z256_point_mul(k, P):
    """G1点标量乘 R = k * P"""
    R = Sm9Point()
    gmssl.sm9_z256_point_mul(byref(R), k, byref(P))
    return R

def z256_point_mul_generator(k):
    """G1点生成元标量乘 R = k * P1"""
    R = Sm9Point()
    gmssl.sm9_z256_point_mul_generator(byref(R), k)
    return R

def z256_point_to_uncompressed_octets(P):
    """G1点转非压缩字节串(65字节)"""
    out = (c_uint8 * 65)()
    ret = gmssl.sm9_z256_point_to_uncompressed_octets(byref(P), out)
    _check(ret, "sm9_z256_point_to_uncompressed_octets失败")
    return bytes(out)

def z256_point_from_uncompressed_octets(data):
    """从非压缩字节串(65字节)构造G1点"""
    if len(data) != 65:
        raise ValueError(f"需要65字节，实际{len(data)}字节")
    P = Sm9Point()
    ret = gmssl.sm9_z256_point_from_uncompressed_octets(byref(P), (c_uint8 * 65)(*data))
    _check(ret, "sm9_z256_point_from_uncompressed_octets失败")
    return P

# === G1 仿射点 ===

class Sm9AffinePoint(Structure):
    _fields_ = [
        ("X", c_uint64 * 4),
        ("Y", c_uint64 * 4),
    ]

def z256_point_copy_affine(P_affine):
    """将仿射点复制为Jacobian点"""
    R = Sm9Point()
    gmssl.sm9_z256_point_copy_affine(byref(R), byref(P_affine))
    return R

def z256_point_add_affine(P, Q_affine):
    """Jacobian点 + 仿射点"""
    R = Sm9Point()
    gmssl.sm9_z256_point_add_affine(byref(R), byref(P), byref(Q_affine))
    return R

def z256_point_sub_affine(P, Q_affine):
    """Jacobian点 - 仿射点"""
    R = Sm9Point()
    gmssl.sm9_z256_point_sub_affine(byref(R), byref(P), byref(Q_affine))
    return R

def z256_point_to_affine(P):
    """Jacobian点转仿射点"""
    Q = Sm9AffinePoint()
    gmssl.sm9_z256_point_to_affine(byref(Q), byref(P))
    return Q

# === E'(F_p^2) 扭曲曲线点 (G2群) ===

class Sm9TwistPoint(Structure):
    _fields_ = [
        ("X", c_uint64 * 8),   # Fp2 = 2 * 4
        ("Y", c_uint64 * 8),
        ("Z", c_uint64 * 8),
    ]

def z256_twist_generator():
    """获取G2群生成元P2"""
    gmssl.sm9_z256_twist_generator.restype = POINTER(Sm9TwistPoint)
    ptr = gmssl.sm9_z256_twist_generator()
    return ptr.contents

def z256_twist_point_to_uncompressed_octets(P):
    """G2点转非压缩字节串(129字节)"""
    out = (c_uint8 * 129)()
    ret = gmssl.sm9_z256_twist_point_to_uncompressed_octets(byref(P), out)
    _check(ret, "sm9_z256_twist_point_to_uncompressed_octets失败")
    return bytes(out)

def z256_twist_point_from_uncompressed_octets(data):
    """从非压缩字节串(129字节)构造G2点"""
    if len(data) != 129:
        raise ValueError(f"需要129字节，实际{len(data)}字节")
    P = Sm9TwistPoint()
    ret = gmssl.sm9_z256_twist_point_from_uncompressed_octets(byref(P), (c_uint8 * 129)(*data))
    _check(ret, "sm9_z256_twist_point_from_uncompressed_octets失败")
    return P

def z256_twist_point_from_hex(hex_str):
    """从十六进制字符串构造G2点"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_from_hex(byref(R), hex_str.encode('ascii'))
    return R

def z256_twist_point_is_at_infinity(P):
    """判断G2点是否为无穷远点"""
    return gmssl.sm9_z256_twist_point_is_at_infinity(byref(P))

def z256_twist_point_set_infinity():
    """返回G2群无穷远点"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_set_infinity(byref(R))
    return R

def z256_twist_point_get_xy(P):
    """获取G2点的仿射坐标"""
    x = Fp2()
    y = Fp2()
    gmssl.sm9_z256_twist_point_get_xy(byref(P), x, y)
    return x, y

def z256_twist_point_equ(P, Q):
    """判断两个G2点是否相等"""
    return gmssl.sm9_z256_twist_point_equ(byref(P), byref(Q))

def z256_twist_point_is_on_curve(P):
    """判断G2点是否在曲线上"""
    return gmssl.sm9_z256_twist_point_is_on_curve(byref(P))

def z256_twist_point_neg(P):
    """G2点取负"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_neg(byref(R), byref(P))
    return R

def z256_twist_point_dbl(P):
    """G2点倍点"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_dbl(byref(R), byref(P))
    return R

def z256_twist_point_add(P, Q):
    """G2点加法"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_add(byref(R), byref(P), byref(Q))
    return R

def z256_twist_point_sub(P, Q):
    """G2点减法"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_sub(byref(R), byref(P), byref(Q))
    return R

def z256_twist_point_add_full(P, Q):
    """G2点完全加法（无预计算）"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_add_full(byref(R), byref(P), byref(Q))
    return R

def z256_twist_point_mul(k, P):
    """G2点标量乘"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_mul(byref(R), k, byref(P))
    return R

def z256_twist_point_mul_generator(k):
    """G2点生成元标量乘"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_mul_generator(byref(R), k)
    return R

# === 配对运算相关 ===

def z256_eval_g_tangent(P, Q):
    """计算切线"""
    R = Sm9TwistPoint()
    lw = Fp2()  # 实际需要3个Fp2，但这里用同一个数组
    gmssl.sm9_z256_eval_g_tangent(byref(R), lw, byref(P), byref(Q))
    return R, lw

def z256_eval_g_line(P, T, Q):
    """计算直线"""
    R = Sm9TwistPoint()
    lw = Fp2()
    pre = (c_uint64 * 40)()  # 5 * 8
    gmssl.sm9_z256_eval_g_line(byref(R), lw, pre, byref(P), byref(T), byref(Q))
    return R, lw

def z256_eval_g_line_no_pre(P, T, Q):
    """计算直线（无预计算）"""
    R = Sm9TwistPoint()
    lw = Fp2()
    gmssl.sm9_z256_eval_g_line_no_pre(byref(R), lw, byref(P), byref(T), byref(Q))
    return R, lw

def z256_fp12_line_mul(a, lw):
    """Fp12乘直线函数值"""
    r = Fp12()
    gmssl.sm9_z256_fp12_line_mul(r, a, lw)
    return r

def z256_twist_point_pi1(P):
    """扭曲点pi1映射"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_pi1(byref(R), byref(P))
    return R

def z256_twist_point_pi2(P):
    """扭曲点pi2映射"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_pi2(byref(R), byref(P))
    return R

def z256_twist_point_neg_pi2(P):
    """扭曲点负pi2映射"""
    R = Sm9TwistPoint()
    gmssl.sm9_z256_twist_point_neg_pi2(byref(R), byref(P))
    return R

def z256_final_exponent_hard_part(f):
    """最终求幂的困难部分"""
    r = Fp12()
    gmssl.sm9_z256_final_exponent_hard_part(r, f)
    return r

def z256_final_exponent(f):
    """最终求幂"""
    r = Fp12()
    gmssl.sm9_z256_final_exponent(r, f)
    return r

def z256_pairing(Q, P):
    """计算配对 e(Q, P)，Q∈G2, P∈G1"""
    r = Fp12()
    gmssl.sm9_z256_pairing(r, byref(Q), byref(P))
    return r