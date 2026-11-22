#!/usr/bin/env python3
# binowl MCP 服务器回归测试（M1.5，2026-11-15）
# 期望值来源：verify_mcp.py 首跑 35/35 PASS 的真实输出——readelf -h/-lW/-SW/-d
# 与 pefile 现场采集的权威快照（dyn_ls: DYN/0x10b0/14段/27节/NX·FullRELRO·PIE；
# minidll.dll: AMD64/DLL/2节/4导出/无Rich）
import os
HERE = os.path.dirname(os.path.abspath(__file__))          # tests/
REPO = os.path.dirname(HERE)                               # repo root

import json
import subprocess
import sys

import pytest
from conftest import SKIP_CLI, has_sample
from binowl.mcp import tool_info, tool_map  # noqa: E402  纯函数直测（协议层）；进程级交叉由 McpStdio 测试覆盖

FIX = os.path.join(HERE, "fixtures")
DYN_LS = os.path.join(FIX, "dyn_ls")   # M2.5d：自构造可分发替代 bin_ls.elf
MINIDLL = os.path.join(FIX, "minidll.dll")


class McpStdio:
    """精简 MCP stdio 客户端（与 binowl.mcp 实现独立，进程级交叉）"""

    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "binowl.cli", "mcp"], cwd=REPO,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self._id = 0

    def req(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        assert resp["id"] == self._id
        return resp

    def notify(self, method):
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def tool(self, name, args):
        r = self.req("tools/call", {"name": name, "arguments": args})
        return r["result"]["content"][0]["text"], r["result"].get("isError", False)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def mcp():
    s = McpStdio()
    s.req("initialize", {"protocolVersion": "2025-06-18"})
    s.notify("notifications/initialized")
    return s


# ── E1 握手 ──────────────────────────────────────────────────

def test_handshake_protocol_echo():
    s = McpStdio()
    r = s.req("initialize", {"protocolVersion": "2025-06-18"})
    init = r["result"]
    assert init["protocolVersion"] == "2025-06-18"
    assert "tools" in init["capabilities"]
    assert init["serverInfo"]["name"] == "binowl"
    s.close()


def test_handshake_unknown_version_falls_back():
    s = McpStdio()
    r = s.req("initialize", {"protocolVersion": "1999-01-01"})
    assert r["result"]["protocolVersion"] == "2025-06-18"
    s.close()


def test_initialized_notification_no_response():
    """通知不产生响应：下一条响应必须属于后续请求的 id"""
    s = McpStdio()
    s.req("initialize", {"protocolVersion": "2025-06-18"})
    s.notify("notifications/initialized")
    s._id = 77   # 人为跳跃，确保 id 唯一
    r = s.req("tools/list")
    assert r["id"] == 78 and "tools" in r["result"]
    s.close()


# ── E2 工具清单 ──────────────────────────────────────────────

def test_tools_list_schema():
    s = mcp()
    tools = s.req("tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {"binowl_info", "binowl_map"} <= names
    for t in tools:
        if t["name"] in ("binowl_info", "binowl_map"):
            assert t["description"].strip()
            assert t["inputSchema"]["type"] == "object"
            assert "path" in t["inputSchema"]["required"]
    s.close()


# ── E3 info × readelf 权威锚点 ───────────────────────────────

def test_info_elf_anchors():
    """dyn_ls：readelf -h/-lW/-d 定标快照（verify_mcp 35/35 证据）"""
    s = mcp()
    text, err = s.tool("binowl_info", {"path": DYN_LS})
    assert not err
    info = json.loads(text)
    assert info["format"] == "ELF" and info["arch"] == "x86-64"
    assert info["type"] == "DYN" and info["entry"] == "0x10b0"
    assert info["phdrs"] == 14 and info["sections"] == 27
    assert info["security"] == {"nx": "enabled", "relro": "full", "pie": "yes"}
    assert info["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert info["needed"] == ["libc.so.6"]   # readelf -d 实采（dyn_ls 单 NEEDED）
    s.close()


def test_info_pe_anchors():
    """minidll.dll：pefile 定标（AMD64/DLL/2节/4导出/构造无 Rich）"""
    s = mcp()
    text, err = s.tool("binowl_info", {"path": MINIDLL})
    assert not err
    info = json.loads(text)
    assert info["format"] == "PE" and info["arch"] == "AMD64" and info["bits"] == 64
    assert info["type"] == "DLL" and info["entry_rva"] == "0x1000"
    assert info["image_base"] == "0x140000000" and info["sections"] == 2
    assert info["exports"] == {"dll": "minidll.dll", "base": 1, "nfuncs": 4}
    assert info["rich"] is None
    s.close()


# ── E4 map × readelf/pefile ──────────────────────────────────

def test_map_elf_segments():
    s = mcp()
    text, err = s.tool("binowl_map", {"path": DYN_LS, "kind": "segments"})
    assert not err
    segs = json.loads(text)
    assert segs["kind"] == "segments" and segs["count"] == 14
    types = [e["type"] for e in segs["entries"]]
    assert types[0] == "PHDR" and types[-1] == "GNU_RELRO"
    assert types.count("LOAD") == 4          # readelf -lW：4 个 LOAD
    assert "GNU_STACK" in types and "GNU_PROPERTY" in types  # readelf 风格命名
    s.close()


def test_map_elf_sections_and_default_kind():
    s = mcp()
    text, err = s.tool("binowl_map", {"path": DYN_LS, "kind": "sections"})
    assert not err
    assert json.loads(text)["count"] == 27   # readelf -SW
    text, _ = s.tool("binowl_map", {"path": DYN_LS})
    assert json.loads(text)["kind"] == "segments"  # kind 缺省值
    s.close()


def test_map_pe_sections():
    s = mcp()
    text, err = s.tool("binowl_map", {"path": MINIDLL})
    assert not err
    pmap = json.loads(text)
    assert pmap["count"] == 2
    assert [e["name"] for e in pmap["entries"]] == [".text", ".edata"]
    assert pmap["entries"][0]["rva"] == "0x1000"
    s.close()


# ── E5 负路径与连接健壮性 ────────────────────────────────────

def test_tool_error_not_found():
    s = mcp()
    text, err = s.tool("binowl_info", {"path": "/no/such/file"})
    assert err and "不存在" in text and "Traceback" not in text
    s.close()


def test_tool_error_text_file(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("not a binary\n" * 4)
    s = mcp()
    text, err = s.tool("binowl_info", {"path": str(p)})
    assert err and "无法识别" in text and "Traceback" not in text
    s.close()


def test_tool_error_missing_path_and_bad_kind():
    s = mcp()
    text, err = s.tool("binowl_info", {})
    assert err and "path" in text
    text, err = s.tool("binowl_map", {"path": DYN_LS, "kind": "bogus"})
    assert err
    s.close()



# ── limitations 协议（2026-11-22 REA 对标吸收；键恒存在，条目 {code, detail}）──

def test_limitations_protocol_constant_key():
    """协议恒在：任意样本 info/map 载荷必含 limitations 键（空数组合法）"""
    for path in (DYN_LS, MINIDLL):
        info = tool_info(path)
        m = tool_map(path)
        assert "limitations" in info and isinstance(info["limitations"], list)
        assert "limitations" in m
        assert all(set(e) == {"code", "detail"} for e in info["limitations"])


def test_limitations_dyn_ls_stripped_only():
    """干净动态 PIE：单条 stripped（符号分析受限是真实边界）；无指纹类误报"""
    codes = [e["code"] for e in tool_info(DYN_LS)["limitations"]]
    assert codes == ["stripped"]


def test_limitations_fp_upx_packed():
    """UPX 样本：无节表 + 无动态段双条目——packed 语义边界完整声明"""
    codes = [e["code"] for e in tool_info(os.path.join(FIX, "fp_upx"))["limitations"]]
    assert codes == ["no-section-table", "static-binary"]


def test_limitations_antidebug_observations_not_findings():
    """anti_debug_demo：观察层判据显式声明「not findings」（R43 分层进协议）"""
    codes = [e["code"] for e in tool_info(os.path.join(FIX, "anti_debug_demo"))["limitations"]]
    assert "anti-debug-observations" in codes


def test_limitations_pe_no_rich():
    """无 Rich 头的 PE：编译器指纹降级边界显式声明（minipe 自构造无 Rich）"""
    codes = [e["code"] for e in tool_info(os.path.join(FIX, "minipe.exe"))["limitations"]]
    assert "no-rich-header" in codes

def test_server_survives_errors():
    """连续工具级错误后连接存活且结果正确（两层错误语义分离的意义）"""
    s = mcp()
    s.tool("binowl_info", {"path": "/no/such/file"})
    s.tool("binowl_info", {})
    text, err = s.tool("binowl_info", {"path": DYN_LS})
    assert not err and json.loads(text)["entry"] == "0x10b0"
    s.close()


def test_unknown_method_jsonrpc_error_and_ping():
    s = mcp()
    r = s.req("bogus/method")
    assert r["error"]["code"] == -32601
    r = s.req("ping")
    assert "result" in r
    s.close()


def test_cli_mcp_short_circuit_preserves_file_analysis():
    """双身份不串台：`binowl mcp` 短路不影响单文件分析路径（58 断言行为）"""
    r = subprocess.run([sys.executable, "-m", "binowl.cli", DYN_LS],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0
    assert "Entry: 0x10b0" in r.stdout and "Checksec:" in r.stdout
