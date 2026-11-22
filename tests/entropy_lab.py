#!/usr/bin/env python3
"""entropy_lab.py — 青铜任务：UPX 加壳前后熵分布对照实验（2026-11-18）

实验设计（阶段一 #8 加壳样本动手课实操）：
  三组同源对照（plain vs UPX），量化「压缩 = 熵搬运」假设：
  1. 全文件 Shannon 熵（bit/byte，上限 8.0）
  2. ELF 节级熵（binowl.elf.parse 节表 → .text/.rodata）
  3. 4KB 块熵分布（min/median/max）——压缩段应高位平坦，原生段有低熵洞

  假设（可证伪）：
    H1: UPX 样本全文件熵 > 7.0（压缩数据接近理论上限）
    H2: plain 样本 .text 熵在 5.0-6.8（代码有结构冗余，达不到 8）
    H3: UPX 样本中位块熵 > plain 样本最大块熵（压缩把低熵洞也消灭）
"""
import math
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from binowl import elf, fingerprint  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
PAIRS = [("fp_plain", "fp_upx"), ("fp_static", "fp_upx_static"),
         ("cli-64.exe", "cli64_upx.exe")]


def entropy(blob):
    """Shannon 熵（bit/byte）：H = -Σ p(x)·log2 p(x)"""
    if not blob:
        return 0.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    n = len(blob)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def block_entropy(data, bs=4096):
    """4KB 块熵序列（最后一块不足 bs 照算）"""
    return [entropy(data[i:i + bs]) for i in range(0, len(data), bs)]


def section_entropy(path):
    """ELF 节级熵 [(name, entropy)]——UPX 无节表返回 []"""
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        return []
    r = elf.parse(path)
    out = []
    for (name, _t, addr, off, size) in r["sections"]:
        if name in (".text", ".rodata", ".data") and size:
            out.append((name, round(entropy(data[off:off + size]), 3)))
    return out


def report(name):
    p = os.path.join(FIX, name)
    data = open(p, "rb").read()
    blocks = block_entropy(data)
    fp = fingerprint.fingerprint(p)
    return {
        "name": name, "size": len(data),
        "entropy": round(entropy(data), 3),
        "blocks_min": round(min(blocks), 2), "blocks_med": round(statistics.median(blocks), 2),
        "blocks_max": round(max(blocks), 2),
        "sections": section_entropy(p),
        "family": fp["family"],
    }


print("%-16s %8s %7s | %7s %7s %7s | %s" %
      ("sample", "size", "H(file)", "blk-min", "blk-med", "blk-max", "sections (.text/.rodata/.data)"))
print("-" * 110)
results = {}
for plain, upx in PAIRS:
    for n in (plain, upx):
        r = report(n)
        results[n] = r
        print("%-16s %8d %7.3f | %7.2f %7.2f %7.2f | %s" %
              (r["name"], r["size"], r["entropy"], r["blocks_min"],
               r["blocks_med"], r["blocks_max"],
               r["sections"] if r["sections"] else "(无节表/PE)"))

print("\n== 假设检验 ==")
h1 = all(results[u]["entropy"] > 7.0 for _, u in PAIRS)
print("H1 UPX 全文件熵 > 7.0        :", "PASS" if h1 else "FAIL",
      "—", ", ".join("%s=%.3f" % (u, results[u]["entropy"]) for _, u in PAIRS))
plain_texts = [h for n in ("fp_plain", "fp_static") for (nm, h) in results[n]["sections"]
               if nm == ".text"]
h2 = all(5.0 <= h <= 6.8 for h in plain_texts)
print("H2 plain .text 熵 ∈ [5.0,6.8] :", "PASS" if h2 else "FAIL",
      "—", plain_texts)
h3 = all(results[u]["blocks_med"] > results[p]["blocks_max"]
         for p, u in [("fp_plain", "fp_upx"), ("fp_static", "fp_upx_static")])
print("H3 UPX 块中位熵 > plain 块最大 :", "PASS" if h3 else "FAIL",
      "—", "; ".join("%s med=%.2f vs %s max=%.2f" %
                     (u, results[u]["blocks_med"], p, results[p]["blocks_max"])
                     for p, u in [("fp_plain", "fp_upx"), ("fp_static", "fp_upx_static")]))
sys.exit(0 if (h1 and h2 and h3) else 1)
