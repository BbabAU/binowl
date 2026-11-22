#!/usr/bin/env python3
# binowl.cli — 统一命令行入口（2026-11-14 M1 收口日）
#
# 分诊规则（magic 字节，两级校验）：
#   ELF: 前 4 字节 \x7fELF
#   PE : 前 2 字节 MZ **且** e_lfanew(0x3C) 处 4 字节 PE\0\0
#        —— 双重校验防"MZ 开头但非 PE"的文件误入 pe 通道
# 分发：elf/pe 渲染通道直接复用各模块 main([path])，输出与模块直调逐字节一致。
# 失败语义（分诊工具的崩溃路径必须可控，禁止 traceback 直面用户）：
#   退出码 2 = 分诊失败（不认识/读不了的格式）
#   退出码 3 = 分诊通过但解析失败（截断/损坏等，一行报告异常类型）
import argparse
import os
import struct
import sys

from . import elf, pe


def detect_format(path):
    """返回 'elf' / 'pe' / None。文件级 OSError 由调用方统一处理。"""
    with open(path, "rb") as f:
        head = f.read(0x40)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        with open(path, "rb") as f:
            f.seek(e_lfanew)
            if f.read(4) == b"PE\x00\x00":
                return "pe"
    return None


def main(argv=None):
    """统一 CLI 入口：`binowl <file>` 分诊解析 / `binowl mcp` MCP 服务器 / `binowl fp <file>` 净室指纹。返回进程退出码（0 成功 / 2 文件级 / 3 解析级，R30 语义分层）。"""
    # M1.5（2026-11-15）：`binowl mcp` 启动 MCP stdio 服务器（CLI+MCP 双身份）。
    # 手动短路而非 argparse subparsers——保持单文件位置参数行为与 58 断言逐字节兼容。
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "mcp":
        from . import mcp
        return mcp.serve()
    # M2.1（2026-11-16）：`binowl fp <file>` 净室指纹（UPX/编译器/stripped）
    if argv and argv[0] == "fp":
        from . import fingerprint
        return fingerprint.main(argv[1:])
    ap = argparse.ArgumentParser(
        prog="binowl.cli",
        description="binowl 统一入口：自动识别 ELF/PE 并输出分诊解析报告")
    ap.add_argument("file", help="待分析的二进制文件")
    ap.add_argument("--format", choices=["auto", "elf", "pe"], default="auto",
                    help="强制指定格式（默认 auto：magic 字节自动识别）")
    args = ap.parse_args(argv)

    if not os.path.exists(args.file):
        print("binowl: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        fmt = args.format if args.format != "auto" else detect_format(args.file)
    except OSError as e:
        print("binowl: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    if fmt is None:
        print("binowl: %s: 无法识别的格式（非 ELF / 非 PE）" % args.file,
              file=sys.stderr)
        return 2
    mod = {"elf": elf, "pe": pe}[fmt]
    try:
        mod.main([args.file])
    except Exception as e:  # 解析失败也要一行可读报告，退出码与分诊失败区分
        print("binowl: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
