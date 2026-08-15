# Copyright 2024 The GmLLC Project. All Rights Reserved.
#
# GmLLC - 基于GmSSL DLL的低层Python接口库
# 提供DLL导出表中所有函数的ctypes绑定

class GmLLCError(Exception):
    """GmLLC 库基础异常"""
    pass

class NativeError(GmLLCError):
    """DLL内部错误（函数返回非0/非1）"""
    pass

class StateError(GmLLCError):
    """密码学状态错误（如未初始化、状态不匹配）"""
    pass

class ValueError(GmLLCError):
    """参数值错误"""
    pass