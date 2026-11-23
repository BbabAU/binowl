"""binowl.map 单元测试（M3.1，2026-11-24）：ELF/PE 内存映射视图与地址换算的边界断言。

权威对拍（readelf -lW / pefile）在 artifacts/2026-11-24/verify_m31_map.py 做一次性全等验证并落证据；
本文件固化的是不依赖外部工具的结构性边界：LOAD 条目字段、vaddr→offset 四类落点、头区 1:1、
填充尾映射（与 pefile 一致——A4 实测 9/9）、虚拟尾 None（修复 rva_to_raw 越界 bug 的回归锁；pefile 在此处给出越界偏移）。
"""
import os

import pytest

from binowl import cli, elf, map as bmap, pe
from conftest import SKIP_CLI, has_sample

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
ELFS = ["dyn_ls", "dyn_nopie", "dyn_pie", "dyn_static", "dyn_norelro", "dyn_execstack",
        "fp_plain", "fp_static", "fp_stripped", "fp_upx", "fp_upx_static",
        "anti_debug_demo", "bin_ls.elf"]
PES = ["minipe.exe", "minidll.dll", "cli-64.exe", "cli64_upx.exe", "minipe_fakerich.exe"]


def _param(name):
    """分发边界（conftest）：不可再生产物不入公开仓——公开克隆/CI 中显式 skip 且理由明示，本地全量跑。"""
    reason = SKIP_CLI if name.startswith("cli") else (
        "bin_ls.elf is a system binary, excluded from repo (CHARTER #4)")
    return pytest.param(name, marks=pytest.mark.skipif(not has_sample(name), reason=reason))


ELFS_P = [_param(n) for n in ELFS]
PES_P = [_param(n) for n in PES]


def _elf(name):
    return elf.parse(os.path.join(FIX, name))


def _pe(name):
    return pe.parse(os.path.join(FIX, name))


# ---------------- ELF：映射视图 ----------------

@pytest.mark.parametrize("name", ELFS_P)
def test_elf_loads_only_pt_load_and_fields_match_phdrs(name):
    """视图条目只含 PT_LOAD，且 (offset, vaddr, filesz, memsz) 与 elf.parse 的 6 字段 phdrs 逐项相等；memsz >= filesz。"""
    r = _elf(name)
    loads = bmap.elf_memory_map(r)["loads"]
    assert loads, "没有任何 LOAD 段"
    assert len(loads) == sum(1 for p in r["phdrs"] if p[0] == 1)
    for e in loads:
        _t, _fl, off, va, fsz, msz = r["phdrs"][e["index"]]
        assert r["phdrs"][e["index"]][0] == 1
        assert (e["offset"], e["vaddr"], e["filesz"], e["memsz"]) == (off, va, fsz, msz)
        assert msz >= fsz
        assert e["file_backed"] == (va, va + fsz)
        assert e["zero_fill"] == ((va + fsz, va + msz) if msz > fsz else None)


@pytest.mark.parametrize("name", ELFS_P)
def test_elf_vaddr_to_offset_four_boundaries(name):
    """每个 LOAD：起点→offset、末字节→offset+filesz-1、零填充起点与 memsz 末字节不得由本段背衬；1<<60 未映射。"""
    r = _elf(name)
    for i, (t, _fl, off, va, fsz, msz) in enumerate(r["phdrs"]):
        if t != 1:
            continue
        if fsz:
            assert bmap.elf_vaddr_to_offset(r, va) == (off, i)
            assert bmap.elf_vaddr_to_offset(r, va + fsz - 1) == (off + fsz - 1, i)
        hit = bmap.elf_vaddr_to_offset(r, va + fsz)
        assert hit is None or hit[1] != i
        if msz > fsz:
            hit = bmap.elf_vaddr_to_offset(r, va + msz - 1)
            assert hit is None or hit[1] != i
    assert bmap.elf_vaddr_to_offset(r, 1 << 60) is None


@pytest.mark.parametrize("name", ELFS_P)
def test_elf_entry_has_file_backing_and_page_alignment(name):
    """入口点必有文件背衬；页区间 = vaddr 向下对齐 / (vaddr+memsz) 向上对齐；overlaps 键存在。"""
    r = _elf(name)
    mv = bmap.elf_memory_map(r)
    assert bmap.elf_vaddr_to_offset(r, r["entry"]) is not None
    for e in mv["loads"]:
        assert e["page_start"] == e["vaddr"] & ~0xFFF
        assert e["page_end"] == (e["vaddr"] + e["memsz"] + 0xFFF) & ~0xFFF
        assert e["page_end"] - e["page_start"] >= e["memsz"]
    assert "overlaps" in mv and mv["format"] == "ELF"


# ---------------- PE：映射视图 ----------------

@pytest.mark.parametrize("name", PES_P)
def test_pe_memory_map_fields_match_parse(name):
    """节条目 (rva, vsize, rawptr, rawsize, name) 与 pe.parse 逐项相等；va = ImageBase + rva；头区条目 1:1。"""
    r = _pe(name)
    mv = bmap.pe_memory_map(r)
    assert mv["image_base"] == r["image_base"] and mv["entry_rva"] == r["entry"]
    assert mv["headers"]["vsize"] == r["size_headers"] == mv["headers"]["rawsize"]
    assert len(mv["sections"]) == len(r["sections"])
    for e, (va, vs, rp, rs, nm) in zip(mv["sections"], r["sections"]):
        assert (e["rva"], e["vsize"], e["rawptr"], e["rawsize"], e["name"]) == (va, vs, rp, rs, nm)
        assert e["va"] == r["image_base"] + va
        assert e["file_backed"] == ((va, va + rs) if rs else None)
        assert e["zero_fill"] == ((va + rs, va + vs) if vs > rs else None)


def test_pe_rva_to_offset_headers_one_to_one():
    """头区 [0, SizeOfHeaders) 与文件 1:1（修复前返回 None）。"""
    r = _pe("minipe.exe")
    assert bmap.pe_rva_to_offset(r, 0) == 0
    assert bmap.pe_rva_to_offset(r, r["size_headers"] - 1) == r["size_headers"] - 1


def test_pe_rva_to_offset_section_backed_including_padding_tail():
    """minipe .text va=0x1000 vs=0x100 raw=0x400 rs=0x200：RawSize 范围内全部有背衬，含 VSize 之外的填充尾（物理准确：loader 映射页含这些字节；pefile 同样映射，A4 实测一致）。"""
    r = _pe("minipe.exe")
    assert bmap.pe_rva_to_offset(r, 0x1000) == 0x400
    assert bmap.pe_rva_to_offset(r, 0x10FF) == 0x4FF
    assert bmap.pe_rva_to_offset(r, 0x11FF) == 0x5FF


def test_pe_rva_to_offset_virtual_tail_none():
    """虚拟尾 [va+RawSize, va+VSize) 无文件背衬 → None。修复前 rva_to_raw 返回越界偏移（evidence_m31_rva_to_raw_before.log）。"""
    assert pe.rva_to_raw(0x1200, [(0x1000, 0x2000, 0x400, 0x200, ".data")]) is None
    assert pe.rva_to_raw(0x2FFF, [(0x1000, 0x2000, 0x400, 0x200, ".data")]) is None
    r = {"size_headers": 0x200, "sections": [(0x1000, 0x2000, 0x400, 0x200, ".data")]}
    assert bmap.pe_rva_to_offset(r, 0x1200) is None and bmap.pe_rva_to_offset(r, 0x2FFF) is None


@pytest.mark.skipif(not has_sample("cli-64.exe"), reason=SKIP_CLI)
def test_pe_rva_to_offset_virtual_tail_none_real_sample():
    """真实样本回归锁：cli-64.exe .data va=0x5000 vs=0x648 raw=[0x3000,0x3200)——修复前 0x5200→0x3200 越界偏移。"""
    rc = _pe("cli-64.exe")
    assert bmap.pe_rva_to_offset(rc, 0x51FF) == 0x31FF
    assert bmap.pe_rva_to_offset(rc, 0x5200) is None


# ---------------- CLI ----------------

def test_cli_map_exit_codes(tmp_path):
    """R30：文件不存在 / 非 ELF·PE → 2。"""
    assert bmap.main(["/nonexistent/file"]) == 2
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"MZ\x00\x00" + b"\x00" * 0x40)
    assert bmap.main([str(bad)]) == 2


def test_cli_map_renders_and_to_offset(capsys):
    """ELF：LOAD 区间/文件背衬/零填充/页区间 + --to-offset 两种落点；PE：头区条目 + 填充尾标注 + RVA 换算。"""
    assert bmap.main([os.path.join(FIX, "dyn_ls"), "--to-offset", "0x10b0",
                      "--to-offset", "0x100000"]) == 0
    out = capsys.readouterr().out
    assert "binowl map: ELF memory map" in out
    assert "zero-fill [0x4060, 0x4068)" in out and "pages [0x3000, 0x5000)" in out
    # 期望段号从 phdrs 推导而非硬编码（首版硬编码 #2 实为 #3：R31 期望提取纪律）
    r = elf.parse(os.path.join(FIX, "dyn_ls"))
    exp = next(i for i, p in enumerate(r["phdrs"]) if p[0] == 1 and p[3] <= 0x10b0 < p[3] + p[4])
    assert "to-offset: va 0x10b0 -> file 0x10b0 (LOAD #%d)" % exp in out
    assert "entry 0x10b0 -> file offset 0x10b0 (LOAD #%d)" % exp in out
    assert "to-offset: va 0x100000 -> <no file backing>" in out
    assert bmap.main([os.path.join(FIX, "minipe.exe"), "--to-offset", "0x1000",
                      "--to-offset", "0x40", "--to-offset", "0x1200"]) == 0
    out = capsys.readouterr().out
    assert "binowl map: PE memory map (ImageBase 0x140000000" in out
    assert "[headers] rva [0x0, 0x200)" in out and "padding tail 0x100 beyond vsize" in out
    assert "to-offset: rva 0x1000 -> file 0x400" in out
    assert "to-offset: rva 0x40 -> file 0x40" in out
    assert "to-offset: rva 0x1200 -> <no file backing>" in out


def test_cli_dispatches_map_subcommand(capsys):
    """`binowl map <file>` 经 cli.main 手动短路到 map.main（与 mcp/fp 同模式）。"""
    assert cli.main(["map", os.path.join(FIX, "dyn_ls")]) == 0
    assert "binowl map" in capsys.readouterr().out
