"""binowl.fingerprint — 净室二进制指纹（M2.1，2026-11-16）

净室观察法：判据只用外部可见特征（魔数字节 / 节名 / 头部结构），不做解压、
不猜测内部语义。判据全部经 2026-11-16 实测定标（TASK_m2_fingerprint.md）：

  UPX-ELF : b"UPX!" 存在 AND e_shnum==0 AND b"$Info: ... packed with the UPX"
            版本从 b"$Id: UPX (\\d+\\.\\d+)" 提取（5.02 ↔ upx 5.0.2 实测）
  UPX-PE  : 节名含 UPX0 AND UPX1 AND b"UPX!" 存在（无 $Id 串 → 版本 None）
  副作用  : ELF 节表消失 → compiler/stripped 诚实降级 None
  ELF compiler : .comment 节首条 C 串（"GCC: (…) ..."，与 readelf -p 逐字一致）
  ELF stripped : .symtab 节有无（strip 保留 .comment——fp_stripped 实测）
  PE compiler   : Rich 头存在 → "MSVC(Rich)"（UPX 保留 DOS stub，Rich 跨壳幸存）

M2.3（2026-11-18）anti_debug_hints：ELF 五家族反调试净室判据（4 召回 + 1 观察），
findings/observations 分层输出（R38），UPX/PE 诚实降级 None。
"""
import re
import struct
import sys

UPX_MAGIC = b"UPX!"
UPX_INFO = b"$Info: This file is packed with the UPX"
UPX_ID = re.compile(rb"\$Id: UPX (\d+\.\d+) ")

# ---- M2.3 反调试判据常量（anti_debug_criteria.md，2026-11-17 实测定标） ----
RDTSC = b"\x0f\x31"
ENV_STRINGS = (b"LD_PRELOAD", b"TracerPid:", b"/proc/self/status")
PLT_ENTRY_SZ = 16
# cmp $0xCC 字节模式集（观察层，非反汇编级）：imm8/imm32 × reg/内存直寻形式
CC_CMP_PATTERNS = tuple(
    [b"\x3c\xcc", b"\x3d\xcc\x00\x00\x00"]
    + [bytes((0x80, 0xF0 | r_, 0xCC)) for r_ in range(8)]           # cmp r8, 0xCC
    + [bytes((0x80, 0x30 | r_, 0xCC)) for r_ in range(8)]           # cmp byte [reg], 0xCC
    + [bytes((0x81, 0xF0 | r_, 0xCC, 0, 0, 0)) for r_ in range(8)]  # cmp r32, 0xCC
)
ANTI_DEBUG_NEG_NOTE = ("判据经构造样本 ground truth + 系统负样本（2026-11-17）"
                       "及 binowl fixtures 全集（2026-11-18）实测定标；"
                       "hints ≠ detection，观察层需动态确认")


def _elf_shnum(data):
    """净室直读 ELF 头 e_shnum（ELF64@0x3C / ELF32@0x2C），不依赖解析器"""
    off = 0x3C if data[4] == 2 else 0x2C
    return struct.unpack_from("<H", data, off)[0]


def _elf_upx(data):
    if (UPX_MAGIC in data and _elf_shnum(data) == 0 and UPX_INFO in data):
        m = UPX_ID.search(data)
        return "UPX", (m.group(1).decode() if m else None), [
            "UPX! magic", "e_shnum==0 (节表被剥)", UPX_INFO.decode()]
    return None, None, []


def _elf_comment_and_symtab(data):
    """净室自读节表：返回 (.comment 首条串|None, has_symtab|None)
    shnum==0 → (None, None)。独立于 elf.parse，判据零依赖深解析器。"""
    if _elf_shnum(data) == 0:
        return None, None
    end = "<" if data[5] == 1 else ">"
    (_t, _m, _v, _e, e_phoff, e_shoff, _f, _eh, _pe, _pn, _se,
     e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    shdrs = []
    for i in range(e_shnum):
        (sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size,
         _lk, _in, _al, _es) = struct.unpack_from(end + "IIQQQQIIQQ", data, e_shoff + i * _se)
        shdrs.append((sh_name, sh_type, sh_offset, sh_size))
    if not shdrs or e_shstrndx >= len(shdrs):
        return None, None
    sn_off, sn_size = shdrs[e_shstrndx][2], shdrs[e_shstrndx][3]
    strtab = data[sn_off:sn_off + sn_size]

    def name_of(sh):
        e = strtab.index(b"\x00", sh[0])
        return strtab[sh[0]:e].decode("ascii", "replace")

    comment, has_symtab = None, False
    for sh in shdrs:
        nm = name_of(sh)
        if nm == ".comment" and comment is None:
            blob = data[sh[2]:sh[2] + sh[3]]
            comment = blob.split(b"\x00")[0].decode("ascii", "replace")
        elif nm == ".symtab":
            has_symtab = True
    return comment, has_symtab


def _pe_section_names(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    n = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    off = e_lfanew + 24 + optsz
    return [data[off + i * 40:off + i * 40 + 8].rstrip(b"\x00").decode(errors="replace")
            for i in range(n)]


def decode_rich_compiler(pairs):
    """M2.2（2026-11-17）：Rich comp.id → (family, compiler_str, entries)。

    结构层（100% 可证伪）：compid → prodid=hi16 / build=lo16 / count。
    family 判据（TASK_m2_msvc_decode.md，值域交叉）：
      msvc_modern : 存在 prodid∈[0x80,0x105] 且 build≥0x7000 的条目
                    （ESET VB2019：VS2015+ msobj140 含新段；cli-64 实测 0x93/0x101–0x105 全落值域）
      msvc_legacy : 全部 prodid≤216 且 build<0x8000（skochinsky 表覆盖时代）
      其他        : ("unknown", None)
    顶层串：msvc_modern → "MSVC(modern, b<build>)"，b 取 [0x80,0xFF] 子域
    （编译器段净室近似，O1 待 msobj.lib 精化）条目中 count 最大者。
    已知限制：VS2010 SP1 时代（cl build 40219）理论上可落 modern 值域——
    手头无该时代样本，O1 收口。单 prodid 不给名（147=Implib900(旧)/compiler(新) 复用冲突）。
    """
    entries = [{"prodid": c >> 16, "build": c & 0xFFFF, "count": n}
               for (c, n) in pairs]
    modern = [e for e in entries
              if 0x0080 <= e["prodid"] <= 0x0105 and e["build"] >= 0x7000]
    if modern:
        comp_entry = max((e for e in modern if e["prodid"] <= 0xFF),
                         key=lambda e: e["count"], default=None)
        b = comp_entry["build"] if comp_entry else modern[0]["build"]
        return "msvc_modern", "MSVC(modern, b%d)" % b, entries
    legacy = all(e["prodid"] <= 216 and e["build"] < 0x8000 for e in entries)
    if legacy:
        return "msvc_legacy", "MSVC(legacy, %d tools)" % len(entries), entries
    return "unknown", None, entries


def _elf_exec_sections(data):
    """净室直读节表 → 可执行节 [(name, vaddr, file_off, size)]（SHF_EXECINSTR=0x4）。

    SHT_NOBITS（.bss）无文件内容，跳过。shnum==0（UPX）→ 空列表。
    """
    if _elf_shnum(data) == 0:
        return []
    end = "<" if data[5] == 1 else ">"
    (_t, _m, _v, _e, _ph, e_shoff, _f, _eh, _pe, _pn, e_shentsize,
     e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    shdrs = []
    for i in range(e_shnum):
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         _lk, _in, _al, _es) = struct.unpack_from(end + "IIQQQQIIQQ",
                                                  data, e_shoff + i * e_shentsize)
        shdrs.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))
    if not shdrs or e_shstrndx >= len(shdrs):
        return []
    sn = shdrs[e_shstrndx]
    strtab = data[sn[4]:sn[4] + sn[5]]

    def name_of(sh):
        e = strtab.index(b"\x00", sh[0])
        return strtab[sh[0]:e].decode("ascii", "replace")

    return [(name_of(s), s[3], s[4], s[5]) for s in shdrs
            if s[1] != 8 and s[2] & 0x4]  # 非 NOBITS ∧ EXECINSTR


def _count_in(data, off, size, pat):
    return data[off:off + size].count(pat)


def _plt_targets(r, sym):
    """sym@plt 候选地址集合：{.plt+16*(i+1), .plt.sec+16*i}。

    i = sym 在 .rela.plt 中的序号（0 起）。两种形式并存是因为 CET 编译产物
    （-fcf-protection）call 目标在 .plt.sec（无 PLT0 头，i 直接映射）。
    """
    targets = set()
    sec_vaddr = {s[0]: s[2] for s in r["sections"]}
    for (secname, _off, ents) in r["relocations"]:
        if secname != ".rela.plt":
            continue
        for i, e in enumerate(ents):
            if e[5] == sym:  # e = (offset, info, rtype, tname, sym_idx, sym_nm, ...)
                if ".plt" in sec_vaddr:
                    targets.add(sec_vaddr[".plt"] + PLT_ENTRY_SZ * (i + 1))
                if ".plt.sec" in sec_vaddr:
                    targets.add(sec_vaddr[".plt.sec"] + PLT_ENTRY_SZ * i)
                break
    return targets


def _count_calls_to(data, exec_secs, targets):
    """可执行节中 call rel32（E8）目标 ∈ targets 的计数（call@plt 直调验证）。"""
    n = 0
    for (_nm, va, off, size) in exec_secs:
        blob = data[off:off + size]
        pos = blob.find(b"\xe8")
        while pos != -1:
            if pos + 5 <= len(blob):
                rel = struct.unpack_from("<i", blob, pos + 1)[0]
                if va + pos + 5 + rel in targets:
                    n += 1
            pos = blob.find(b"\xe8", pos + 1)
    return n


def anti_debug_hints(path):
    """M2.3（2026-11-18）：ELF 反调试净室提示——五家族判据（4 召回 + 1 观察）。

    判据来源：artifacts/2026-11-17/anti_debug_criteria.md（构造样本 ground truth
    + 4 系统负样本实测定标）；2026-11-18 净室实现期两项分层修正（R43，见 CHANGELOG）：
    rdtsc 字节级降观察层（bin_ls 跨边界假阳性实证）、env 字符串静态链接降观察层
    （fp_static 的 LD_PRELOAD 归属 glibc）。分层（R38 独立性分层律）：

      findings     高置信召回（净室静态可判）：env-check（动态链接）/ anti-trace /
                   parent-check（medium，容器误报源注明）
      observations 需进一步确认：timing（字节级非指令级）、int3-check（cmp $0xCC
                   字节模式）、env-check（静态链接）、dynsym ptrace 无 PLT 直调

    已知限制：hints ≠ detection；UPX（节表被剥）与 PE 返回 None（诚实降级，
    PE 侧判据不在 M2.3 范围）；间接调用 ptrace（dlsym/函数指针）不在此判据内。
    """
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or _elf_shnum(data) == 0:
        return None
    from . import elf
    r = elf.parse(path)
    findings, observations = [], []

    # 家族4 环境自检（字符串强判据；静态链接降级——字符串归属 glibc 可能）
    # PT_INTERP 无 ⇔ 静态链接（fp_static 实测；LD_PRELOAD 来自静态 glibc dl 代码）
    is_dynamic = any(p[0] == 3 for p in r["phdrs"])
    env_hits = [s.decode() for s in ENV_STRINGS if s in data]
    if env_hits:
        item = {"family": "env-check",
                "evidence": "strings: " + ", ".join(env_hits)}
        if is_dynamic:
            item.update(confidence="high")
            findings.append(item)
        else:
            item.update(confidence="medium",
                        note="静态链接（无 PT_INTERP）：字符串归属 glibc 可能，非反调试意图")
            observations.append(item)

    exec_secs = _elf_exec_sections(data)
    # 家族2 rdtsc 成对计时（字节级扫描，阈值 ≥2）
    # R43：字节命中 ≠ 指令级——bin_ls.elf 实证跨指令边界假阳性（objdump 指令级 0
    # vs 字节级 2），无反汇编器（M4 前）净室不可判指令边界 → 观察层
    n_rdtsc = sum(_count_in(data, off, size, RDTSC)
                  for (_nm, _va, off, size) in exec_secs)
    if n_rdtsc >= 2:
        observations.append({"family": "timing", "confidence": "medium",
                             "evidence": "rdtsc 字节序列 ×%d（可执行节字节扫描）" % n_rdtsc,
                             "note": "字节级匹配非指令级，需反汇编/动态确认"})

    # dynsym 簇（家族5/4b）
    dyn = {s[0] for s in (r["symbols"]["dynsym"] or [])}
    if "ptrace" in dyn:
        n_call = _count_calls_to(data, exec_secs, _plt_targets(r, "ptrace"))
        if n_call:
            findings.append({"family": "anti-trace", "confidence": "high",
                             "evidence": "dynsym ptrace + call <ptrace@plt> ×%d" % n_call})
        else:
            observations.append({"family": "anti-trace", "confidence": "medium",
                                 "evidence": "dynsym ptrace（未定位到 PLT 直调）"})
    if "getppid" in dyn:
        findings.append({"family": "parent-check", "confidence": "medium",
                         "evidence": "dynsym getppid",
                         "note": "容器内 PID1 场景天然触发，需结合上下文"})

    # 家族3 0xCC 陷阱字节自检（观察层）
    n_cc = sum(_count_in(data, off, size, p)
               for p in CC_CMP_PATTERNS for (_nm, _va, off, size) in exec_secs)
    if n_cc:
        observations.append({"family": "int3-check", "confidence": "low",
                             "evidence": "cmp $0xCC 字节模式 ×%d" % n_cc,
                             "note": "需动态确认（字节级匹配，非反汇编；gcc 负样本有已知误报）"})

    return {"findings": findings, "observations": observations,
            "negative_evidence": ANTI_DEBUG_NEG_NOTE}


def fingerprint(path):
    """主入口：返回 {family, packer_version, compiler, stripped, evidence, anti_debug_hints}

    anti_debug_hints（M2.3）：仅未加壳 ELF 有值（五家族判据）；UPX/PE → None 诚实降级。
    """
    data = open(path, "rb").read()
    ev = []
    if data[:4] == b"\x7fELF":
        family, ver, ev = _elf_upx(data)
        if family == "UPX":
            # 副作用：节表消失 → compiler/stripped 不可判定（诚实降级）
            compiler = stripped = None
            ev.append("节表消失 → compiler/stripped 不可判定")
        else:
            compiler, has_sym = _elf_comment_and_symtab(data)
            stripped = None if has_sym is None else (not has_sym)
            if compiler:
                ev.append(".comment: " + compiler)
            if stripped is not None:
                ev.append(".symtab %s → stripped=%s" %
                          ("缺失" if stripped else "存在", stripped))
        anti = None if family == "UPX" else anti_debug_hints(path)
        if anti is None and family == "UPX":
            ev.append("节表被剥 → 反调试静态判据不可用")
        return {"format": "ELF", "family": family, "packer_version": ver,
                "compiler": compiler, "stripped": stripped, "evidence": ev,
                "anti_debug_hints": anti}
    if data[:2] == b"MZ":
        names = _pe_section_names(data)
        if names is None:
            raise ValueError("MZ 但无合法 PE 头")
        if "UPX0" in names and "UPX1" in names and UPX_MAGIC in data:
            family, ver = "UPX", None
            ev = ["节名 UPX0+UPX1", "UPX! magic"]
        else:
            family, ver = None, None
        from . import pe
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        rich = pe.parse_rich_header(data, e_lfanew)
        if rich is not None:
            fam_rich, compiler, entries = decode_rich_compiler(rich["pairs"])
            ev.append("Rich 头 %d 对 → %s（DOS stub 幸存）" % (len(entries), fam_rich))
            ev.append("compiler: " + compiler)
        else:
            compiler = None
        return {"format": "PE", "family": family, "packer_version": ver,
                "compiler": compiler, "stripped": None, "evidence": ev,
                "anti_debug_hints": None}
    raise ValueError("非 ELF / 非 PE（magic=%s）" % data[:4].hex())


def main(argv=None):
    """指纹 CLI 入口（`binowl fp <file>`）：打印 family/compiler/stripped + 证据链；退出码遵循 R30（0 成功 / 2 文件级 / 3 解析级）。"""
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv:
        print("usage: binowl fp <file>", file=sys.stderr)
        return 2
    path = argv[0]
    import os
    if not os.path.exists(path):
        print("binowl fp: %s: 文件不存在" % path, file=sys.stderr)
        return 2
    try:
        fp = fingerprint(path)
    except Exception as e:  # R30：解析异常 exit 3，与文件级错误（2）分层
        print("binowl fp: %s: 指纹失败(%s: %s)" % (path, type(e).__name__, e), file=sys.stderr)
        return 3
    fam = fp["family"] or "none(known)"
    ver = fp["packer_version"]
    fam_full = fam + ("/" + ver if ver else "")
    print("fingerprint: %s" % fam_full)
    print("  compiler: %s" % (fp["compiler"] or "unknown"))
    s = fp["stripped"]
    print("  stripped: %s" % ("unknown" if s is None else str(s).lower()))
    for e in fp["evidence"]:
        print("  evidence: %s" % e)
    ad = fp["anti_debug_hints"]
    if ad is None:
        print("  anti-debug: n/a（壳内/PE 判据不可用，诚实降级）")
    else:
        print("  anti-debug: %d finding(s), %d observation(s) %s" %
              (len(ad["findings"]), len(ad["observations"]), "（hints ≠ detection）"
               if ad["findings"] or ad["observations"] else ""))
        for f in ad["findings"]:
            print("    [%s] %s: %s" % (f["confidence"], f["family"], f["evidence"]))
        for o in ad["observations"]:
            print("    [%s] %s: %s — %s" %
                  (o["confidence"], o["family"], o["evidence"], o.get("note", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
