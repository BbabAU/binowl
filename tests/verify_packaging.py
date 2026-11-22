#!/usr/bin/env python3
# M2.5a 可安装性验证器（2026-11-18）——TASK_m25a.md G1–G5 逐条可证伪执行。
# 独立于 pytest 常绿套件（venv/网络依赖不适合 CI 矩阵外的快速回归）。
# 用法：python3 tests/verify_packaging.py   （在 repo 根目录执行）
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(REPO, "tests", "fixtures")
# 注意：本验证器依赖 repo 外的本地 artifacts 快照与 upx 工具链，不在 CI 矩阵内跑。
ART = os.environ.get("BINOWL_ARTIFACTS",
                     os.path.join(REPO, "..", "artifacts", "2026-11-18"))
VENV = "/tmp/binowl_venv_m25a"
PYV = os.path.join(VENV, "bin", "python")
REKIT = os.path.join(VENV, "bin", "binowl")
# 4 fixtures 覆盖四种形态：系统 ELF / PE 导出 / UPX 压缩 ELF / 反调试正样本
FIXTURES = ["bin_ls.elf", "minidll.dll", "fp_upx", "anti_debug_demo"]

results = []          # (gid, name, ok, detail)


def log(name, text):
    with open(os.path.join(ART, name), "w", encoding="utf-8") as f:
        f.write(text)
    return text


def check(gid, name, ok, detail=""):
    results.append((gid, name, bool(ok), detail))
    print("%s %-38s %s%s" % (gid, name, "PASS" if ok else "FAIL",
                             (" | " + detail) if detail else ""))


def run(cmd, cwd=None, stdin=None, timeout=240):
    return subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True,
                          text=True, timeout=timeout)


# ── G1 元数据：tomllib 静态断言 ──────────────────────────────
import tomllib  # py3.11+；本验证器仅在 3.12 开发机运行
with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
    meta = tomllib.load(f)
p = meta["project"]
g1 = [
    ("name == binowl", p["name"] == "binowl", p["name"]),
    ("version 为 dynamic（单一来源）", "version" in p["dynamic"],
     "dynamic=" + ",".join(p["dynamic"])),
    ("license 非空（SPDX 占位）", bool(p.get("license")), str(p.get("license"))),
    ("scripts.binowl == binowl.cli:main",
     p["scripts"]["binowl"] == "binowl.cli:main", p["scripts"]["binowl"]),
    ("packages 显式 == ['binowl']",
     meta["tool"]["setuptools"]["packages"] == ["binowl"], ""),
    ("dynamic 版本锚定 binowl.__version__",
     meta["tool"]["setuptools"]["dynamic"]["version"]["attr"]
     == "binowl.__version__", ""),
]
for name, ok, detail in g1:
    check("G1", name, ok, detail)

# ── G2 净室安装 ────────────────────────────────────────────
shutil.rmtree(VENV, ignore_errors=True)
r = run([sys.executable, "-m", "venv", VENV])
check("G2", "venv 创建", r.returncode == 0, r.stderr.strip()[:120])
r = run([PYV, "-m", "pip", "install", "--no-input", REPO], cwd="/tmp")
log("evidence_m25a_install.log",
    "$ python -m venv %s && pip install %s (cwd=/tmp)\nrc=%d\n%s\n%s"
    % (VENV, REPO, r.returncode, r.stdout, r.stderr))
check("G2", "pip install . 一次成功", r.returncode == 0,
      (r.stderr.strip().splitlines() or [""])[-1][:160])

r = run([REKIT, "--help"], cwd="/tmp")
check("G2", "binowl --help 可执行", r.returncode == 0 and "binowl" in r.stdout,
      "rc=%d" % r.returncode)

r = run([PYV, "-m", "pip", "show", "binowl"], cwd="/tmp")
ver_installed = next((ln.split(":", 1)[1].strip()
                      for ln in r.stdout.splitlines()
                      if ln.startswith("Version")), "?")
r = run([sys.executable, "-c", "import binowl;print(binowl.__version__)"], cwd=REPO)
ver_source = r.stdout.strip()
check("G2", "版本单一来源一致", ver_installed == ver_source == "0.1.0",
      "installed=%s source=%s" % (ver_installed, ver_source))

r = run([PYV, "-c", "import binowl;print(binowl.__file__)"], cwd="/tmp")
check("G2", "脱离源码树可 import", r.returncode == 0
      and r.stdout.strip().startswith(VENV), r.stdout.strip())

# ── G3 三通道冒烟 + 逐字节一致 ─────────────────────────────
parity_lines = ["# 安装副本 binowl <cmd> vs 源码树 python3 -m binowl.cli <cmd>，stdout 逐字节 diff\n"]
parity_all_ok = True
for fx in FIXTURES:
    path = os.path.join(FIX, fx)
    for cmdname in ("info", "fp"):
        argv = ["fp", path] if cmdname == "fp" else [path]
        ri = run([REKIT] + argv, cwd="/tmp")
        rs = run([sys.executable, "-m", "binowl.cli"] + argv, cwd=REPO)
        same = ri.stdout == rs.stdout and ri.returncode == rs.returncode
        parity_all_ok &= same
        parity_lines.append("%s %s: %s (rc %d vs %d, %d vs %d bytes)"
                            % (fx, cmdname, "IDENTICAL" if same else "DIFF",
                               ri.returncode, rs.returncode,
                               len(ri.stdout), len(rs.stdout)))
        check("G3", "parity %s %s" % (fx, cmdname), same,
              "rc %d==%d" % (ri.returncode, rs.returncode))
log("evidence_m25a_parity.log", "\n".join(parity_lines) + "\n")

# MCP 通道：安装副本在 /tmp 起服务（脱离源码树），行协议 JSON-RPC 握手
mcp = subprocess.Popen([REKIT, "mcp"], cwd="/tmp", stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                       bufsize=1)
reqs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18"}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "binowl_info",
                "arguments": {"path": os.path.join(FIX, "bin_ls.elf")}}},
]
out_lines = []
for msg in reqs:
    mcp.stdin.write(json.dumps(msg) + "\n")
    mcp.stdin.flush()
    out_lines.append(mcp.stdout.readline())
mcp.stdin.close()
mcp.wait(timeout=10)
mcp_log = ("$ cd /tmp && binowl mcp\n" + "".join(
    ">>> " + json.dumps(m) + "\n<<< " + l for m, l in zip(reqs, out_lines)))
log("evidence_m25a_mcp.log", mcp_log)
try:
    init = json.loads(out_lines[0])["result"]
    tools = json.loads(out_lines[1])["result"]["tools"]
    info = json.loads(json.loads(out_lines[2])["result"]["content"][0]["text"])
    check("G3", "MCP 握手/工具清单/调用", init["serverInfo"]["name"] == "binowl"
          and init["protocolVersion"] == "2025-06-18"
          and {"binowl_info", "binowl_map"} <= {t["name"] for t in tools}
          and info["format"] == "ELF" and info["entry"] == "0x6760",
          "server=%s tools=%d entry=%s"
          % (init["serverInfo"]["name"], len(tools), info["entry"]))
except Exception as e:  # noqa: BLE001 —— 验证器要给出一行可读失败
    check("G3", "MCP 握手/工具清单/调用", False, "%s: %s" % (type(e).__name__, e))

# ── G4 回归常绿 ────────────────────────────────────────────
r = run([sys.executable, "-m", "pytest", "-q"], cwd=REPO, timeout=300)
log("evidence_m25a_pytest.log", r.stdout + r.stderr)
check("G4", "源码树 pytest 常绿", "123 passed" in r.stdout,
      (r.stdout.strip().splitlines() or ["?"])[-1])

# ── 汇总 ──────────────────────────────────────────────────
n_fail = sum(1 for x in results if not x[2])
print("\n== M2.5a 汇总：%d 项，FAIL %d ==" % (len(results), n_fail))
sys.exit(1 if n_fail else 0)
