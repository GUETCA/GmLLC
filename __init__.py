# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# GmLLC - 基于GmSSL DLL的低层Python接口库
# 提供DLL导出表中所有函数的ctypes绑定，方便比赛分析调用
#
# 设计原则：
#   1. 直接封装DLL导出函数，不做高层抽象
#   2. 按模块分类：sm9, sm9_z256, zuc, sm2, sm2_z256, sm3, sm4
#   3. 低级接口直接暴露，允许调用者自由组合

from ctypes import *
from ctypes.util import find_library
import sys
import os

# === DLL 加载 ===
_DLL_NAME = "gmssl"
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_dll():
    """加载GmSSL动态库"""
    # 优先从包目录加载gmssl.dll
    dll_path = os.path.join(_PACKAGE_DIR, "gmssl.dll")
    if os.path.exists(dll_path):
        try:
            return cdll.LoadLibrary(dll_path)
        except OSError:
            pass
    # 回退到系统搜索
    lib_path = find_library(_DLL_NAME)
    if lib_path is None:
        raise RuntimeError(
            "无法找到GmSSL动态库。请将gmssl.dll放在项目目录下，"
            "或安装GmSSL: https://github.com/guanzhi/GmSSL"
        )
    return cdll.LoadLibrary(lib_path)

gmssl = _load_dll()

# === 平台相关 ===
if sys.platform == 'win32':
    libc = cdll.LoadLibrary(find_library('msvcrt'))
else:
    libc = cdll.LoadLibrary(find_library('c'))

# === 版本信息 ===
__version__ = "1.0.0"
GMLLC_VERSION = __version__

def version_num():
    """获取GmSSL库版本号"""
    return gmssl.gmssl_version_num()

def version_str():
    """获取GmSSL库版本字符串"""
    gmssl.gmssl_version_str.restype = c_char_p
    return gmssl.gmssl_version_str().decode('ascii')

# === 常量 ===
DO_ENCRYPT = True
DO_DECRYPT = False
DO_SIGN = True
DO_VERIFY = False

# === 工具函数 ===
def rand_bytes(size):
    """生成随机字节"""
    buf = create_string_buffer(size)
    gmssl.rand_bytes(buf, c_size_t(size))
    return buf.raw

def _check(ret, msg="DLL调用失败"):
    """检查DLL函数返回值，非0/非1时抛出异常"""
    if ret != 1:
        from .error import NativeError
        raise NativeError(msg)

# === 子模块延迟导入 ===
def _lazy_import(module_name):
    import importlib
    return importlib.import_module(f'.{module_name}', __package__)

__all__ = [
    'gmssl', 'libc', '__version__', 'GMLLC_VERSION',
    'version_num', 'version_str', 'rand_bytes',
    'DO_ENCRYPT', 'DO_DECRYPT', 'DO_SIGN', 'DO_VERIFY',
]