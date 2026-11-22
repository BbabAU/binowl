"""test_fingerprint.py — M2.1 净室指纹回归（2026-11-16）

断言来源：tests/fixtures/m2_manifest.json（build_samples.py 构造时刻权威锁定）
+ 专项锚点（UPX 副作用降级 / fakerich 陷阱 / elf.parse 无节表修复回归）。
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
from binowl import elf, fingerprint  # noqa: E402

MAN = json.load(open(os.path.join(HERE, "m2_manifest.json")))
BY = {s["name"]: s for s in MAN["samples"]}


def _fp(name):
    return fingerprint.fingerprint(os.path.join(FIX, name))


# ---- 参数化：16 样本三元组全量对拍（F2+F3 固化） ----
# 分发边界：不可再生产物（bin_ls/cli-64/cli64_upx）本地全测，公开克隆环境自动剔除
@pytest.mark.parametrize("s", [m for m in MAN["samples"] if has_sample(m["name"])],
                         ids=[s["name"] for s in MAN["samples"] if has_sample(s["name"])])
def test_manifest_triplet(s):
    got = _fp(s["name"])
    exp = s["expect"]
    assert got["family"] == exp["family"]
    assert got["packer_version"] == exp["packer_version"]
    assert got["compiler"] == exp["compiler"]
    assert got["stripped"] == exp["stripped"]


# ---- 专项锚点 ----
def test_upx_elf_version_extraction():
    """UPX-ELF 版本 5.02 ↔ upx 5.0.2（$Id 串提取）"""
    fp = _fp("fp_upx")
    assert fp["family"] == "UPX" and fp["packer_version"] == "5.02"
    assert any("e_shnum==0" in e for e in fp["evidence"])


def test_upx_side_effect_honest_degrade():
    """UPX 副作用：节表消失 → compiler/stripped 双 None（诚实降级，不猜）"""
    for n in ("fp_upx", "fp_upx_static"):
        fp = _fp(n)
        assert fp["compiler"] is None and fp["stripped"] is None


@pytest.mark.skipif(not has_sample("cli-64.exe"), reason=SKIP_CLI)
def test_upx_pe_rich_survives():
    """UPX 保留 DOS stub → Rich 跨壳幸存（cli64_upx vs cli-64 全等 11 对）。
    M2.2 期望表演进（CHANGELOG 2026-11-17）：compiler 串 MSVC(Rich) → MSVC(modern, b30729)"""
    assert _fp("cli64_upx.exe")["compiler"] == "MSVC(modern, b30729)"
    assert _fp("cli-64.exe")["compiler"] == "MSVC(modern, b30729)"


@pytest.mark.skipif(not has_sample("cli-64.exe"), reason=SKIP_CLI)
def test_decode_rich_compiler_structure():
    """M2.2 F1：结构解码 11 对 → (prodid, build, count) 与 parse_rich_header 同源一致"""
    import struct
    from binowl import pe, fingerprint
    d = open(os.path.join(FIX, "cli-64.exe"), "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    rich = pe.parse_rich_header(d, e)
    fam, comp, entries = fingerprint.decode_rich_compiler(rich["pairs"])
    assert fam == "msvc_modern" and comp == "MSVC(modern, b30729)"
    assert len(entries) == 11
    e0 = entries[0]
    assert (e0["prodid"], e0["build"], e0["count"]) == (0x93, 30729, 16)
    assert sum(x["count"] for x in entries) > 100  # Import0×69 在内


def test_decode_rich_compiler_legacy_and_unknown():
    """M2.2 F2 分支：legacy 表内旧时代条目 → msvc_legacy；空/野值 → unknown"""
    fam, comp, _ = fingerprint.decode_rich_compiler([(11 << 16 | 1234, 5)])
    assert fam == "msvc_legacy" and "legacy" in comp
    fam2, comp2, _ = fingerprint.decode_rich_compiler([(0xF000 << 16 | 9, 1)])
    assert fam2 == "unknown" and comp2 is None


def test_fakerich_trap():
    """伪 Rich 负样本（有 Rich^key 字节无 DanS 锚）不得误报 MSVC"""
    fp = _fp("minipe_fakerich.exe")
    assert fp["family"] is None and fp["compiler"] is None


def test_binls_no_comment_trap():
    """dyn_ls 经 objcopy -R .comment（复刻发行版构建）——单特征缺失 ≠ 加壳，family 仍 None"""
    fp = _fp("dyn_ls")
    assert fp["family"] is None and fp["compiler"] is None and fp["stripped"] is True


def test_strip_keeps_comment():
    """strip 保留 .comment（fp_stripped 实测锚点）"""
    fp = _fp("fp_stripped")
    assert fp["compiler"] == BY["fp_stripped"]["expect"]["compiler"]
    assert fp["stripped"] is True


def test_elf_parse_zero_shnum_regression():
    """M1 缺口修复回归：无节表 ELF（UPX）不再 IndexError，sections 置空"""
    r = elf.parse(os.path.join(FIX, "fp_upx"))
    assert r["sections"] == [] and r["symbols"]["symtab"] is None


def test_cli_fp_subcommand():
    """CLI `binowl fp` 3 正样本 exit 0 + 非法输入 exit 码分层（R30）"""
    for n in ("fp_upx", "fp_upx_static", "cli64_upx.exe"):
        if not has_sample(n):
            continue  # cli64_upx.exe provenance audit pending M2.5d (CHARTER #4)
        r = subprocess.run([sys.executable, "-m", "binowl.cli", "fp", os.path.join(FIX, n)],
                           capture_output=True, text=True, cwd=ROOT)
        assert r.returncode == 0, r.stderr
        assert "fingerprint: UPX" in r.stdout
    r = subprocess.run([sys.executable, "-m", "binowl.cli", "fp", "/nonexistent"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 2
