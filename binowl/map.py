#!/usr/bin/env python3
"""binowl.map — M3 map&patch 第一刀：内存映射视图 + 地址换算（2026-11-24）。

回答的问题：加载器把文件铺进内存时，哪段地址对应文件哪段字节？
  ELF：以 PT_LOAD 为单位——[p_vaddr, p_vaddr+p_filesz) 有文件背衬
       （offset = p_offset + (va - p_vaddr)），[p_vaddr+p_filesz, p_vaddr+p_memsz) 是零填充（.bss）。
  PE ：以节为单位——[va, va+RawSize) 有文件背衬，[va+RawSize, va+VSize) 零填充；
       头区 [0, SizeOfHeaders) 与文件 1:1；VA = ImageBase + RVA（默认布局，ASLR 下需加实际基址）。
结论边界：静态推演的默认布局——不含运行时 ASLR 重排，不含加载器自映射的 vdso/stack/heap；
         相邻 LOAD 的页级重叠如实上报（overlaps），不判对错。
"""
import argparse
import os
import sys

from . import elf, pe
from .cli import detect_format

PAGE = 0x1000


def pflags_str(f):
    """p_flags → readelf 风格：R / R E / RW / RW E（与 mcp.pflags_str 同义；map 只依赖 elf/pe，不反向依赖 mcp）。"""
    return (("R" if f & 4 else "") + ("W" if f & 2 else "")
            + (" E" if f & 1 else "")).strip()


def elf_memory_map(r):
    """ELF 内存映射视图。输入 elf.parse() 的返回 dict，输出 {"format","entry","loads","overlaps"}。
    每个 LOAD 条目：vaddr/memsz 描述内存区间 [va, va+memsz)；file_backed 为有文件背衬的子区间 [va, va+filesz)；
    zero_fill 为零填充子区间（无则 None）；page_start/page_end 为页对齐后的真实映射区间。"""
    loads = []
    for i, (t, fl, off, va, fsz, msz) in enumerate(r["phdrs"]):
        if t != 1:                                   # PT_LOAD
            continue
        loads.append({"index": i, "flags": pflags_str(fl), "vaddr": va,
                      "offset": off, "filesz": fsz, "memsz": msz,
                      "file_backed": (va, va + fsz),
                      "zero_fill": (va + fsz, va + msz) if msz > fsz else None,
                      "page_start": va & ~(PAGE - 1),
                      "page_end": (va + msz + PAGE - 1) & ~(PAGE - 1)})
    overlaps = [(a["index"], b["index"]) for a, b in zip(loads, loads[1:])
                if a["page_end"] > b["page_start"]]
    return {"format": "ELF", "entry": r["entry"], "loads": loads, "overlaps": overlaps}


def elf_vaddr_to_offset(r, vaddr):
    """ELF 虚拟地址 → (文件偏移, 段号)。落在零填充区或任何 LOAD 之外返回 None（无文件背衬）。
    同一 vaddr 被多个 LOAD 的文件背衬覆盖时取先出现者（规范二进制不应出现，overlaps 另报页级重叠）。"""
    for i, (t, _fl, off, va, fsz, _msz) in enumerate(r["phdrs"]):
        if t == 1 and va <= vaddr < va + fsz:
            return off + (vaddr - va), i
    return None


def pe_memory_map(r):
    """PE 内存映射视图。输出 {"format","image_base","entry_rva","headers","sections"}；
    每条目含 rva/vsize（内存区间 [rva, rva+vsize)）、rawptr/rawsize（文件区间）、file_backed、zero_fill、
    page_start/page_end、va（= ImageBase + rva，默认布局）。头区作为 index -1 的条目，与文件 1:1。"""
    base = r["image_base"]

    def entry(idx, name, va, vs, rp, rs):
        return {"index": idx, "name": name, "rva": va, "vsize": vs,
                "rawptr": rp, "rawsize": rs,
                "file_backed": (va, va + rs) if rs else None,
                "zero_fill": (va + rs, va + vs) if vs > rs else None,
                "page_start": va & ~(PAGE - 1),
                "page_end": (va + max(vs, rs) + PAGE - 1) & ~(PAGE - 1),
                "va": base + va}

    headers = entry(-1, "[headers]", 0, r["size_headers"], 0, r["size_headers"])
    sections = [entry(i, nm, va, vs, rp, rs)
                for i, (va, vs, rp, rs, nm) in enumerate(r["sections"])]
    return {"format": "PE", "image_base": base, "entry_rva": r["entry"],
            "headers": headers, "sections": sections}


def pe_rva_to_offset(r, rva):
    """PE RVA → 文件偏移。头区 [0, SizeOfHeaders) 1:1；节区委托 pe.rva_to_raw（仅 RawSize 范围内有文件背衬）；其余 None。"""
    if 0 <= rva < r["size_headers"]:
        return rva
    return pe.rva_to_raw(rva, r["sections"])


def _rng(lo, hi):
    return "[0x%x, 0x%x)" % (lo, hi)


def render_elf(mv, r):
    """ELF 视图文本：每个 LOAD 的内存区间 / 文件背衬 / 零填充 / 页区间，附 entry 落点。"""
    out = ["== binowl map: ELF memory map (static default layout) =="]
    hit = elf_vaddr_to_offset(r, mv["entry"])
    out.append("entry 0x%x -> %s" % (mv["entry"], "file offset 0x%x (LOAD #%d)" % hit
                                     if hit else "<no file backing>"))
    for e in mv["loads"]:
        out.append("LOAD #%-2d %-4s vaddr %s memsz 0x%x" % (
            e["index"], e["flags"], _rng(e["vaddr"], e["vaddr"] + e["memsz"]), e["memsz"]))
        out.append("            file %s  offset = 0x%x + (va - 0x%x)" % (
            _rng(e["offset"], e["offset"] + e["filesz"]), e["offset"], e["vaddr"]))
        out.append("            zero-fill %s  pages %s" % (
            _rng(*e["zero_fill"]) if e["zero_fill"] else "none",
            _rng(e["page_start"], e["page_end"])))
    out.append("page-level overlaps: %s" % (", ".join("#%d/#%d" % o for o in mv["overlaps"])
                                            if mv["overlaps"] else "none"))
    return "\n".join(out)


def render_pe(mv):
    """PE 视图文本：头区 + 每节的内存区间 / 文件背衬 / 零填充 / 页区间，VA 列 = ImageBase + RVA。"""
    out = ["== binowl map: PE memory map (ImageBase 0x%x, entry RVA 0x%x) ==" % (
        mv["image_base"], mv["entry_rva"])]
    for e in [mv["headers"]] + mv["sections"]:
        tag = "1:1" if e["index"] == -1 else ("padding tail 0x%x beyond vsize" % (e["rawsize"] - e["vsize"])
                                               if e["rawsize"] > e["vsize"] else "0x%x" % e["rawsize"])
        out.append("%-9s rva %s vsize 0x%-5x va 0x%x" % (
            e["name"], _rng(e["rva"], e["rva"] + e["vsize"]), e["vsize"], e["va"]))
        out.append("          file %s %s  zero-fill %s  pages %s" % (
            _rng(*e["file_backed"]) if e["file_backed"] else "none", tag,
            _rng(*e["zero_fill"]) if e["zero_fill"] else "none",
            _rng(e["page_start"], e["page_end"])))
    return "\n".join(out)


def main(argv=None):
    """`binowl map <file> [--to-offset ADDR]...`：打印内存映射视图并做地址换算（ELF 传虚拟地址 / PE 传 RVA）。
    退出码：0 成功 / 2 文件级（不存在、非 ELF·PE）/ 3 解析级（截断、损坏）——R30 语义分层。"""
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(prog="binowl map",
                                 description="内存映射视图：ELF LOAD 段 / PE 节 + 头区；--to-offset 做地址→文件偏移换算")
    ap.add_argument("file", help="待分析的 ELF / PE 文件")
    ap.add_argument("--to-offset", metavar="ADDR", action="append", default=[],
                    help="ELF 虚拟地址 / PE RVA（支持 0x 前缀），可重复；输出文件偏移或 <no file backing>")
    args = ap.parse_args(argv)
    if not os.path.exists(args.file):
        print("binowl: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        fmt = detect_format(args.file)
    except OSError as e:
        print("binowl: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    if fmt is None:
        print("binowl: %s: 无法识别的格式（非 ELF / 非 PE）" % args.file, file=sys.stderr)
        return 2
    try:
        if fmt == "elf":
            r = elf.parse(args.file)
            mv = elf_memory_map(r)
            print(render_elf(mv, r))
            for a in args.to_offset:
                hit = elf_vaddr_to_offset(r, int(a, 0))
                print("to-offset: va %s -> %s" % (
                    a, "file 0x%x (LOAD #%d)" % hit if hit else "<no file backing> (zero-fill / unmapped)"))
        else:
            r = pe.parse(args.file)
            mv = pe_memory_map(r)
            print(render_pe(mv))
            for a in args.to_offset:
                off = pe_rva_to_offset(r, int(a, 0))
                print("to-offset: rva %s -> %s" % (
                    a, "file 0x%x" % off if off is not None else "<no file backing> (zero-fill / unmapped)"))
    except Exception as e:
        print("binowl: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
