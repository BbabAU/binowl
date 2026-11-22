"""test_antidebug.py — M2.3 anti_debug_hints 回归（2026-11-18）

断言锚点：
- 正样本全召回（demo 4 家族：3 findings + 2 observations，R43 修正后分层）
- 负样本零误报（召回层，9 ELF fixtures 参数化）
- 诚实降级（UPX 壳内 / PE → None）
- PLT 定位单测（.rela.plt[5] → .plt+16×6 = 0x1080，objdump 对拍锚定）
- 弱符号弃用回归（demo 有 getenv 但不得报 env 弱判据——11-17 判据表）
- CLI / MCP 集成
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, ROOT)

from conftest import SKIP_CLI, has_sample
from binowl import elf, fingerprint, mcp  # noqa: E402

DEMO = os.path.join(FIX, "anti_debug_demo")
NEG_ELFS = [n for n in ["dyn_ls", "dyn_pie", "dyn_nopie", "dyn_static", "dyn_norelro",
            "dyn_execstack", "fp_plain", "fp_stripped", "fp_static"] if has_sample(n)]


def _ad(path):
    return fingerprint.anti_debug_hints(path)


# ---- F1 正样本全召回 ----
def test_demo_full_recall():
    ad = _ad(DEMO)
    fams = {f["family"]: f for f in ad["findings"]}
    # 3 个召回层家族（R43 修正：timing 降观察层）
    assert {"env-check", "anti-trace", "parent-check"} <= set(fams)
    for f in ad["findings"]:
        assert f["evidence"]  # 每条 evidence 非空
    # confidence 分层：parent-check=medium + 容器 note
    assert fams["parent-check"]["confidence"] == "medium"
    assert "容器" in fams["parent-check"]["note"]
    assert fams["env-check"]["confidence"] == "high"
    assert fams["anti-trace"]["confidence"] == "high"
    # anti-trace 双证据：符号 ∧ PLT 直调计数
    assert "call <ptrace@plt> ×1" in fams["anti-trace"]["evidence"]


def test_demo_observations_layered():
    """R43：timing（字节级）与 int3-check 必须在观察层且带 note"""
    ad = _ad(DEMO)
    obs = {o["family"]: o for o in ad["observations"]}
    assert "timing" in obs and obs["timing"]["confidence"] == "medium"
    assert "指令级" in obs["timing"]["note"]
    assert "int3-check" in obs and obs["int3-check"]["confidence"] == "low"


def test_negative_evidence_field():
    ad = _ad(DEMO)
    assert "定标" in ad["negative_evidence"]  # 判据溯源文案在位


# ---- F2 负样本零误报（召回层）----
@pytest.mark.parametrize("name", NEG_ELFS)
def test_negative_fixtures_clean(name):
    ad = _ad(os.path.join(FIX, name))
    assert ad["findings"] == [], \
        "%s 召回层误报: %s" % (name, [f["family"] for f in ad["findings"]])


def test_timing_datasegment_no_false_positive():
    """负样本强化（M2.5d）：dyn_ls .rodata 数据含 0F 31 字节（rdtsc 编码）——
    数据段字节**不产生** timing 判定（anti_debug_hints 只扫可执行段），observations 零误报。"""
    ad = _ad(os.path.join(FIX, "dyn_ls"))
    assert "timing" not in {o["family"] for o in ad["observations"]}


@pytest.mark.skipif(not has_sample("bin_ls.elf"),
                     reason="bin_ls.elf excluded from repo — R43 original scenario (local only)")
def test_bin_ls_timing_is_observation():
    """R43 根因回归（原始场景，本地环境）：bin_ls .text 字节级 0F31（指令级 0）只能进观察层"""
    ad = _ad(os.path.join(FIX, "bin_ls.elf"))
    assert "timing" in {o["family"] for o in ad["observations"]}


def test_static_env_demoted():
    """静态链接（无 PT_INTERP）：LD_PRELOAD 字符串归属 glibc → 观察层"""
    ad = _ad(os.path.join(FIX, "fp_static"))
    assert "env-check" in {o["family"] for o in ad["observations"]}
    assert "env-check" not in {f["family"] for f in ad["findings"]}


def test_demo_getenv_not_flagged():
    """弱符号弃用回归（11-17 判据表）：demo dynsym 有 getenv 但不得报弱判据"""
    ad = _ad(DEMO)
    all_fams = {x["family"] for x in ad["findings"] + ad["observations"]}
    assert not any("getenv" in fam for fam in all_fams)
    assert "getenv" not in all_fams


# ---- 诚实降级 ----
def test_upx_none():
    assert _ad(os.path.join(FIX, "fp_upx")) is None


def test_pe_none():
    assert _ad(os.path.join(FIX, "minipe.exe")) is None


def test_fingerprint_key_integration():
    fp = fingerprint.fingerprint(DEMO)
    assert fp["anti_debug_hints"]["findings"]
    fp_upx = fingerprint.fingerprint(os.path.join(FIX, "fp_upx"))
    assert fp_upx["anti_debug_hints"] is None
    assert "反调试静态判据不可用" in fp_upx["evidence"][-1]


# ---- PLT 定位单测（objdump 对拍锚定） ----
def test_plt_target_address():
    """.rela.plt 第 6 项（i=5）ptrace → .plt(0x1020)+16×6 = 0x1080"""
    r = elf.parse(DEMO)
    targets = fingerprint._plt_targets(r, "ptrace")
    assert 0x1080 in targets


# ---- F5 CLI + MCP 集成 ----
def test_cli_fp_antidebug_output():
    r = subprocess.run([sys.executable, "-m", "binowl.cli", "fp", DEMO],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    assert "anti-debug: 3 finding(s), 2 observation(s)" in r.stdout
    assert "anti-trace" in r.stdout and "ptrace@plt" in r.stdout


def test_cli_fp_upx_antidebug_na():
    """UPX 样本：诚实降级输出且不崩（R30 退出码 0）"""
    r = subprocess.run([sys.executable, "-m", "binowl.cli", "fp",
                        os.path.join(FIX, "fp_upx")],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    assert "anti-debug: n/a" in r.stdout


def test_mcp_info_antidebug_field():
    info = mcp.tool_info({"path": DEMO})
    ad = info["fingerprint"]["anti_debug_hints"]
    assert ad and {f["family"] for f in ad["findings"]} >= {"anti-trace"}


def test_mcp_info_upx_antidebug_none():
    info = mcp.tool_info({"path": os.path.join(FIX, "fp_upx")})
    assert info["fingerprint"]["anti_debug_hints"] is None
