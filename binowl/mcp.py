#!/usr/bin/env python3
# binowl.mcp — MCP (Model Context Protocol) stdio 服务器（M1.5，2026-11-15）
#
# 设计要点（防坑先行，参照 JSON-RPC 2.0 + MCP stdio 规范）：
#   1. 帧格式：每行一条 JSON，禁止内嵌换行；响应必须 flush（否则客户端死等——经典坑）
#   2. stdout 是协议通道：任何日志/错误信息只走 stderr
#   3. 通知（无 id 字段）不产生响应；带 id 的未知方法 → -32601
#   4. 工具执行错误（文件不存在/格式不识别/解析失败）→ isError:true 的正常响应，
#      协议层错误（未知方法/坏帧）才用 JSON-RPC error —— 两层错误语义分开
#   5. 段名采用 readelf 风格（GNU_EH_FRAME 而非 EH_FRAME），交叉验证可直接对拍
import json
import os
import sys

from . import elf, pe
from .cli import detect_format

# 支持的 MCP 协议版本（新→旧）；客户端版本在列表内则回显，否则回最新
SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
LATEST = SUPPORTED_VERSIONS[0]

# readelf 风格段名表（覆盖 elf.PT_TYPES 的非 GNU 前缀命名，仅 MCP 层使用）
PT_NAMES = dict(elf.PT_TYPES)
PT_NAMES.update({0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
                 0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY"})

MACHINE_ARCH = {62: "x86-64", 183: "AArch64", 40: "ARM", 3: "x86",
                8: "MIPS", 243: "RISC-V", 50: "IA-64"}
ET_NAMES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


class ToolError(Exception):
    """工具级错误 → isError:true 响应（连接存活，服务器不崩）"""


def _require_path(args):
    path = args.get("path")
    if not path:
        raise ToolError("缺少必需参数 path")
    if not os.path.exists(path):
        raise ToolError("文件不存在: %s" % path)
    return path


def _detect(path):
    fmt = detect_format(path)
    if fmt is None:
        raise ToolError("无法识别的格式（非 ELF / 非 PE）: %s" % path)
    return fmt


def pflags_str(f):
    """p_flags → readelf 风格：R / R E / RW / RW E"""
    return (("R" if f & 4 else "") + ("W" if f & 2 else "")
            + (" E" if f & 1 else "")).strip()


# ── 工具实现（纯函数，返回 dict；供 tools/call 与直接复用） ──────────

def _fp_field(path):
    """M2.1（2026-11-16）：净室指纹字段——family/版本/编译器/stripped。
    M2.3（2026-11-18）：新增 anti_debug_hints（findings/observations 分层，R38）。
    fingerprint 内部异常不拖垮 info 主干（防御），返回 None 诚实降级。"""
    from . import fingerprint
    try:
        fp = fingerprint.fingerprint(path)
    except Exception:
        return None
    return {"family": fp["family"], "packer_version": fp["packer_version"],
            "compiler": fp["compiler"], "stripped": fp["stripped"],
            "anti_debug_hints": fp["anti_debug_hints"]}


def _collect_limitations(fmt, r, fp, with_fingerprint=True):
    """REA 式「结论带限制声明」协议（2026-11-22 对标吸收）：每个 info/map 载荷
    恒含 limitations 键（空数组合法），条目 {code, detail} 只陈述结论的边界，
    不做预测。全部条目来自既有的诚实降级点，不新增判断逻辑。
    with_fingerprint=False（map 视图）跳过指纹类条目——指纹结论边界归 info。"""
    lim = []
    if fmt == "elf":
        if not r["sections"]:
            lim.append({"code": "no-section-table",
                        "detail": "section table empty — typical of packed binaries "
                                  "(e.g. UPX); section-based fields degraded"})
        if not r["dynamic"]:
            lim.append({"code": "static-binary",
                        "detail": "no dynamic section; import/needed analysis unavailable"})
        if not with_fingerprint:
            return lim
        if fp is None:
            lim.append({"code": "fingerprint-unavailable",
                        "detail": "fingerprint parser failed; field None (defensive degradation)"})
        elif fp["stripped"]:
            lim.append({"code": "stripped",
                        "detail": "symbol table absent; symbol-level analysis limited "
                                  "to dynamic imports"})
        hints = fp["anti_debug_hints"] if fp else None
        obs = (hints or {}).get("observations") or []
        if obs:
            lim.append({"code": "anti-debug-observations",
                        "detail": "%d byte-level observation(s) without instruction-level "
                                  "confirmation (R43 layering) — not findings" % len(obs)})
    else:  # PE
        if not with_fingerprint:
            return lim
        if fp is None:
            lim.append({"code": "fingerprint-unavailable",
                        "detail": "fingerprint parser failed; field None (defensive degradation)"})
        if r.get("rich") is None:
            lim.append({"code": "no-rich-header",
                        "detail": "Rich header absent (non-MSVC toolchain or stripped); "
                                  "compiler fingerprint relies on weaker signals"})
    return lim


def tool_info(path):
    """MCP 工具 binowl_info：二进制分诊摘要（格式/架构/入口/安全四态/导入导出/Rich/fingerprint 字段 M2.2 起）。纯函数，返回可 JSON 序列化 dict。"""
    path = _require_path(path if isinstance(path, dict) else {"path": path})
    fmt = _detect(path)
    if fmt == "elf":
        r = elf.parse(path)
        data = open(path, "rb").read()
        interp = None
        for (t, _fl, off, _va, fsz) in r["phdrs"]:
            if t == elf.PT_INTERP:
                interp = data[off:off + fsz].rstrip(b"\x00").decode("ascii", "replace")
        sec = r["security"]
        fp = _fp_field(path)
        return {
            "format": "ELF",
            "arch": MACHINE_ARCH.get(r["machine"], "machine_%d" % r["machine"]),
            "bits": 64 if data[4] == 2 else 32,
            "endian": "little" if data[5] == 1 else "big",
            "type": ET_NAMES.get(r["type"], r["type"]),
            "entry": "0x%x" % r["entry"],
            "phdrs": len(r["phdrs"]),
            "sections": len(r["sections"]),
            "security": {"nx": sec["nx"], "relro": sec["relro"], "pie": sec["pie"]},
            "wx_segments": sec["wx_segments"],
            "interpreter": interp,
            "needed": r["dynamic"]["needed"] if r["dynamic"] else [],
            "fingerprint": fp,
            "limitations": _collect_limitations("elf", r, fp),
        }
    r = pe.parse(path)
    fp = _fp_field(path)
    return {
        "format": "PE",
        "arch": r["machine"],
        "bits": 64 if r["magic"] == 0x20B else 32,
        "type": "DLL" if int(r["chars"], 16) & 0x2000 else "EXE",
        "entry_rva": "0x%X" % r["entry"],
        "image_base": "0x%X" % r["image_base"],
        "subsystem": r["subsystem"],
        "sections": r["nsect"],
        "imports": [{"dll": d, "count": len(fns)} for (d, fns) in r["imports"]],
        "exports": None if r["exports"] is None else {
            "dll": r["exports"]["dll"], "base": r["exports"]["base"],
            "nfuncs": r["exports"]["nfuncs"]},
        "rich": None if r["rich"] is None else {
            "key": "0x%08X" % r["rich"]["key"], "pairs": len(r["rich"]["pairs"])},
        "fingerprint": fp,
        "limitations": _collect_limitations("pe", r, fp),
    }


def tool_map(path, kind="segments"):
    """MCP 工具 binowl_map：内存映射视图（kind=segments|sections，ELF 段/节表或 PE 节表）。纯函数，返回可 JSON 序列化 dict。"""
    if not isinstance(path, dict):
        path = {"path": path}
    p = _require_path(path)
    kind = path.get("kind", kind)
    fmt = _detect(p)
    if fmt == "elf":
        r = elf.parse(p)
        if kind == "segments":
            entries = [{"index": i, "type": PT_NAMES.get(t, "PT_%x" % t),
                        "flags": pflags_str(fl), "vaddr": "0x%x" % va,
                        "offset": "0x%x" % off, "filesz": "0x%x" % fsz}
                       for i, (t, fl, off, va, fsz) in enumerate(r["phdrs"])]
        elif kind == "sections":
            entries = [{"index": i, "name": nm, "type": t, "addr": "0x%x" % a,
                        "offset": "0x%x" % o, "size": "0x%x" % s}
                       for i, (nm, t, a, o, s) in enumerate(r["sections"])]
        else:
            raise ToolError("kind 必须是 segments 或 sections，收到: %r" % kind)
        # map 的结论边界 = 结构性条目（指纹类归 info，见 _collect_limitations 签名）
        return {"format": "ELF", "kind": kind, "count": len(entries),
                "entries": entries,
                "limitations": _collect_limitations("elf", r, None,
                                                    with_fingerprint=False)}
    # PE：无 ELF 式段表，映射单元即节
    r = pe.parse(p)
    entries = [{"index": i, "name": nm, "rva": "0x%x" % va, "vsize": "0x%x" % vs,
                "rawptr": "0x%x" % rp, "rawsize": "0x%x" % rs}
               for i, (va, vs, rp, rs, nm) in enumerate(r["sections"])]
    return {"format": "PE", "kind": "sections", "count": len(entries),
            "note": "PE 无 ELF 式段表，map 统一返回节表", "entries": entries,
            "limitations": _collect_limitations("pe", r, None,
                                                with_fingerprint=False)}


TOOLS = [
    {"name": "binowl_info",
     "description": "二进制分诊摘要。ELF：格式/架构/类型/入口/段节数/安全态"
                    "(NX·RELRO·PIE)/动态依赖/解释器；PE：架构/类型/入口RVA/"
                    "映像基址/节表数/导入导出摘要/Rich 头指纹；净室指纹"
                    "(family/编译器/stripped)与反调试提示 anti_debug_hints"
                    "(findings/observations 分层，M2.3 起)。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析文件路径"}},
                     "required": ["path"]}},
    {"name": "binowl_map",
     "description": "内存映射视图。ELF：段表(program headers，含 readelf 风格"
                    "GNU_* 段名)或节表(section headers)；PE：节表(RVA/VSize/"
                    "RawPtr/RawSize)。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析文件路径"},
                                    "kind": {"type": "string",
                                             "enum": ["segments", "sections"],
                                             "description": "segments(默认) 或 sections"}},
                     "required": ["path"]}},
]

_TOOL_FUNCS = {"binowl_info": tool_info, "binowl_map": tool_map}


# ── JSON-RPC 分发 ──────────────────────────────────────────────

def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def handle(msg):
    """处理一条已解析的请求 dict；返回响应 dict 或 None（通知）。"""
    if not isinstance(msg, dict):
        return None
    method = msg.get("method")
    msg_id = msg.get("id")   # None ⇒ 通知（MCP 规范：通知无 id）

    if method == "initialize":
        client_v = (msg.get("params") or {}).get("protocolVersion")
        version = client_v if client_v in SUPPORTED_VERSIONS else LATEST
        return _ok(msg_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "binowl", "version": "0.1.0"}})
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        func = _TOOL_FUNCS.get(name)
        try:
            if func is None:
                raise ToolError("未知工具: %r" % name)
            result = func(args)
        except ToolError as e:
            return _ok(msg_id, {"content": [{"type": "text", "text": str(e)}],
                                "isError": True})
        except Exception as e:  # 解析崩溃也走 isError，连接存活
            return _ok(msg_id, {"content": [{"type": "text",
                                             "text": "%s: %s" % (type(e).__name__, e)}],
                                "isError": True})
        return _ok(msg_id, {"content": [{"type": "text",
                                         "text": json.dumps(result, ensure_ascii=False,
                                                            indent=2)}]})
    # notifications/* 与未知通知：静默忽略；未知方法且带 id：method not found
    if msg_id is None:
        return None
    return _err(msg_id, -32601, "Method not found: %r" % method)


def serve(stdin=None, stdout=None):
    """stdio 主循环。返回 0（客户端断开即结束）。"""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            print("binowl-mcp: 跳过无法解析的帧", file=sys.stderr)
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()   # 不 flush 客户端会死等（协议层第一坑）
    return 0
