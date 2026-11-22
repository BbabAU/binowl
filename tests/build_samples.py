#!/usr/bin/env python3
"""build_samples.py — M2 fingerprint 样本采集器（Vibe Coding 融合首战 #1，2026-11-16）

三段式纪律（SPEC → 生成 → postcheck）：

[SPEC] 重建 6 个构造样本 + 登记 10 个既有 fixtures，共 16 样本（3 正 13 负）。
  manifest schema（tests/fixtures/m2_manifest.json）：
    samples[]: {name, path, kind(elf|pe), build_cmd, sha256,
                expect:{family, packer_version, compiler, stripped},
                expect_source}
  期望值在【构造时刻】以权威工具输出动态锁定（readelf -p .comment 原串 /
  readelf -S SYMTAB 有无 / parse_rich_header），postcheck 时重跑权威命令比对
  ——manifest 是期望快照，postcheck 是可证伪复核，二者独立。

[生成] gcc/strip/upx 构造；UPX 路径 --upx 可覆盖，默认 /tmp/upx-5.0.2-amd64_linux/upx。

[postcheck] (--check) 逐样本：
  a) sha256 与 manifest 一致
  b) family=UPX 样本：文件含 b"UPX!" AND (ELF: e_shnum==0 | PE: 节名含 UPX0+UPX1)
  c) 未加壳 ELF：readelf -p .comment 串 == manifest.compiler（含双 None）；
     readelf -S SYMTAB 有无 == manifest.stripped
  d) 未加壳 PE：parse_rich_header 是否为 None ⇔ manifest.compiler 是否为 None
  输出逐行 PASS/FAIL + 总计数；任何 FAIL → exit 1。
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "tests", "fixtures")
SRC = os.path.join(HERE, "src")
MANIFEST = os.path.join(HERE, "m2_manifest.json")  # 不入 fixtures：保持"fixtures=纯二进制"语义（D1 断言遍历该目录）
FP_C = os.path.join(SRC, "fp.c")

# ---- [SPEC] 样本清单（kind, build 步骤列表）----
CONSTRUCTED = [
    # (name, kind, [(cmd...), ...], family, expect_source)
    ("fp_plain", "elf", [("gcc", "-o", "@OUT", FP_C)], None,
     "readelf -p .comment / readelf -S"),
    ("fp_stripped", "elf", [("gcc", "-o", "@OUT", FP_C), ("strip", "@OUT")], None,
     "strip 保留 .comment（实测）；symtab 无"),
    ("fp_static", "elf", [("gcc", "-static", "-o", "@OUT", FP_C)], None,
     "readelf -p .comment / readelf -S"),
    ("fp_upx", "elf", [("upx", "-o", "@OUT", "@FIX/fp_plain")], "UPX",
     "UPX! 魔数 + e_shnum==0 + $Id: UPX 5.02"),
    ("fp_upx_static", "elf", [("upx", "-o", "@OUT", "@FIX/fp_static")], "UPX",
     "UPX! 魔数 + e_shnum==0 + $Id: UPX 5.02"),
    ("cli64_upx.exe", "pe", [("upx", "-o", "@OUT", "@FIX/cli-64.exe")], "UPX",
     "节名 UPX0+UPX1 + UPX! 魔数；Rich 跨壳幸存"),
]

# 既有 fixtures（name, kind, family 期望）
PREEXISTING = [
    ("bin_ls.elf", "elf", None), ("dyn_pie", "elf", None),
    ("dyn_nopie", "elf", None), ("dyn_static", "elf", None),
    ("dyn_norelro", "elf", None), ("dyn_execstack", "elf", None),
    ("minipe.exe", "pe", None), ("minidll.dll", "pe", None),
    ("minipe_fakerich.exe", "pe", None), ("cli-64.exe", "pe", None),
]

UPX_DEFAULT = "/tmp/upx-5.0.2-amd64_linux/upx"


def sha256(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r


def readelf_comment(path):
    """权威：readelf -p .comment 首条字符串（无节 → None）"""
    r = run(["readelf", "-p", ".comment", path])
    m = re.search(r"\[\s*\d+\]\s+(GCC: .+)", r.stdout)
    return m.group(1) if m else None


def readelf_stripped(path):
    """权威：readelf -S 有无 SYMTAB 节（节表缺失 → None）"""
    r = run(["readelf", "-S", path])
    if "There are no sections in this file" in r.stdout:
        return None
    return ("SYMTAB" not in r.stdout)


def elf_shnum(path):
    d = open(path, "rb").read(0x40)
    assert d[:4] == b"\x7fELF"
    off = 0x3C if d[4] == 2 else 0x2C
    return struct.unpack_from("<H", d, off)[0]


def pe_section_names(path):
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    off = e + 24 + optsz
    return [d[off + i * 40:off + i * 40 + 8].rstrip(b"\x00").decode(errors="replace")
            for i in range(n)]


def upx_version_of(path):
    m = re.search(rb"\$Id: UPX (\d+\.\d+)", open(path, "rb").read())
    return m.group(1).decode() if m else None


def rich_compiler_of(path):
    """M2.2：PE compiler 期望锁定——用权威 pairs 独立重解码（判据与
    fingerprint.decode_rich_compiler 同规格；独立性由 verify 的"期望表 vs
    fingerprint 输出"对拍与 postcheck 的"manifest vs 权威 pairs 重解码"双向保持）"""
    sys.path.insert(0, ROOT)
    from binowl import pe, fingerprint
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    rich = pe.parse_rich_header(d, e)
    if rich is None:
        return None
    return fingerprint.decode_rich_compiler(rich["pairs"])[1]


def build(upx):
    os.makedirs(SRC, exist_ok=True)
    with open(FP_C, "w") as f:  # SPEC 内置源码：足够小 + 有可压缩冗余
        f.write('#include <stdio.h>\n#include <string.h>\n'
                'int check(const char*p){int s=0;for(int i=0;i<(int)strlen(p);i++)'
                's=(s*31+p[i])%1000000007;return s==123456789;}\n'
                'int main(int c,char**v){if(c>1&&check(v[1]))puts("OK");'
                'else puts("NO");return 0;}\n')
    samples = []
    for name, kind, steps, family, src_note in CONSTRUCTED:
        out = os.path.join(FIX, name)
        if os.path.exists(out):
            os.remove(out)  # 幂等：重跑时 UPX 拒绝覆盖既有目标（FileAlreadyExistsException）
        for step in steps:
            cmd = [upx if c == "upx" else c for c in step]
            cmd = [c.replace("@OUT", out).replace("@FIX", FIX) for c in cmd]
            r = run(cmd)
            if r.returncode != 0:
                print("BUILD FAIL: %s\n%s" % (name, r.stdout + r.stderr), file=sys.stderr)
                return None
        samples.append(dict(name=name, kind=kind, build_cmd=" && ".join(" ".join(s) for s in steps),
                            expect=lock_expect(out, kind, family, src_note)))
    for name, kind, family in PREEXISTING:
        p = os.path.join(FIX, name)
        samples.append(dict(name=name, kind=kind, build_cmd="(preexisting fixture)",
                            expect=lock_expect(p, kind, family, "readelf/parse_rich 实测")))
    for s in samples:
        s["path"] = "tests/fixtures/" + s["name"]
        s["sha256"] = sha256(os.path.join(FIX, s["name"]))
    man = {"generated": datetime.datetime.now().isoformat(timespec="seconds"),
           "toolchain": {"gcc": run(["gcc", "--version"]).stdout.splitlines()[0],
                         "upx": run([upx, "--version"]).stdout.splitlines()[0]},
           "samples": samples}
    with open(MANIFEST, "w") as f:
        json.dump(man, f, indent=1, ensure_ascii=False)
    print("built %d samples, manifest -> %s" % (len(samples), MANIFEST))
    return man


def lock_expect(path, kind, family, src_note):
    """构造时刻以权威输出锁定期望三元组（动态、可证伪）"""
    exp = {"family": family, "packer_version": None, "compiler": None, "stripped": None}
    if family == "UPX":
        exp["packer_version"] = upx_version_of(path)
    if kind == "elf":
        if not family:  # 未加壳才有节表可查
            exp["compiler"] = readelf_comment(path)
            exp["stripped"] = readelf_stripped(path)
    else:
        exp["compiler"] = rich_compiler_of(path)
    exp["_source"] = src_note
    return exp


def check(man):
    npass = nfail = 0
    for s in man["samples"]:
        p = os.path.join(ROOT, s["path"])
        errs = []
        if not os.path.exists(p):
            errs.append("file missing")
        else:
            if sha256(p) != s["sha256"]:
                errs.append("sha256 mismatch")
            exp = s["expect"]
            data = open(p, "rb").read()
            if exp["family"] == "UPX":
                if b"UPX!" not in data:
                    errs.append("family=UPX but no UPX! magic")
                if s["kind"] == "elf" and elf_shnum(p) != 0:
                    errs.append("family=UPX but shnum!=0")
                if s["kind"] == "pe":
                    names = pe_section_names(p)
                    if "UPX0" not in names or "UPX1" not in names:
                        errs.append("family=UPX but no UPX0/UPX1 sections")
                if s["kind"] == "elf":
                    v = upx_version_of(p)
                    if v != exp["packer_version"]:
                        errs.append("packer_version %r != %r" % (v, exp["packer_version"]))
            else:
                if s["kind"] == "elf":
                    c, st = readelf_comment(p), readelf_stripped(p)
                    if c != exp["compiler"]:
                        errs.append("compiler %r != %r" % (c, exp["compiler"]))
                    if st != exp["stripped"]:
                        errs.append("stripped %r != %r" % (st, exp["stripped"]))
                else:
                    rc = rich_compiler_of(p)
                    if exp["compiler"] != rc:
                        errs.append("redecode=%r vs compiler=%r" % (rc, exp["compiler"]))
        if errs:
            nfail += 1
            print("FAIL %-22s %s" % (s["name"], "; ".join(errs)))
        else:
            npass += 1
            print("PASS %-22s family=%s compiler=%s stripped=%s" %
                  (s["name"], exp.get("family"), exp.get("compiler"), exp.get("stripped")))
    print("postcheck: %d/%d PASS" % (npass, npass + nfail))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    upx = UPX_DEFAULT
    if "--upx" in sys.argv:
        upx = sys.argv[sys.argv.index("--upx") + 1]
    if "--check" in sys.argv:
        sys.exit(check(json.load(open(MANIFEST))))
    man = build(upx)
    sys.exit(1 if man is None else check(man))
