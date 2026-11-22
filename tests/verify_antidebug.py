#!/usr/bin/env python3
"""verify_antidebug.py — M2.3 三方交叉验证（F3）

对 anti_debug_demo 的每条 binowl finding，用 objdump/readelf/strings 权威工具
独立复现（家族 × 数量全对上才算 PASS）。独立于 binowl 实现——只读子进程输出。
证据等级：observed（本机权威工具输出）。
"""
import json
import re
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # learning/rekit
FIX = os.path.join(ROOT, "tests", "fixtures")
DEMO = os.path.join(FIX, "anti_debug_demo")
sys.path.insert(0, ROOT)

from binowl import fingerprint  # noqa: E402

results = []


def check(item, ok, detail):
    results.append((item, ok, detail))
    print("%-4s %s\n     %s" % ("PASS" if ok else "FAIL", item, detail))


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("%s 失败: %s" % (cmd, r.stderr))
    return r.stdout


ad = fingerprint.anti_debug_hints(DEMO)
fams = {f["family"]: f for f in ad["findings"]}
obs = {o["family"]: o for o in ad["observations"]}

# 1) env-check：strings 独立复现三串
out = run(["strings", DEMO])
hits = [s for s in ("LD_PRELOAD", "TracerPid:", "/proc/self/status")
        if re.search(r"^%s$" % re.escape(s), out, re.M)]
check("F3.1 env-check strings 三串",
      "env-check" in fams and set(hits) == {"LD_PRELOAD", "TracerPid:", "/proc/self/status"},
      "binowl: %s | strings 命中: %s" % (fams.get("env-check", {}).get("evidence"), hits))

# 2) anti-trace：objdump -T 有 ptrace ∧ objdump -d 有 call <ptrace@plt>
sym = run(["objdump", "-T", DEMO])
has_ptrace_sym = bool(re.search(r"\bptrace\b", sym))
dis = run(["objdump", "-d", DEMO])
n_call = len(re.findall(r"call.*<ptrace@plt>", dis))
check("F3.2 anti-trace 符号+PLT 直调",
      "anti-trace" in fams and has_ptrace_sym and n_call >= 1,
      "binowl: %s | objdump -T ptrace=%s, call <ptrace@plt> ×%d" %
      (fams.get("anti-trace", {}).get("evidence"), has_ptrace_sym, n_call))

# 3) parent-check：objdump -T 有 getppid
has_getppid = bool(re.search(r"\bgetppid\b", sym))
check("F3.3 parent-check getppid 符号",
      "parent-check" in fams and has_getppid,
      "binowl: %s | objdump -T getppid=%s" % (fams.get("parent-check", {}).get("evidence"), has_getppid))

# 4) timing：objdump -d 指令级 rdtsc ≥2（观察层；字节级已被 R43 降级——
#    此处验证指令级真值与 binowl 字节级计数的关系）
n_rdtsc_real = len(re.findall(r"\brdtsc\b", dis))
n_rdtsc_bytes = int(re.search(r"×(\d+)", obs.get("timing", {}).get("evidence", "×0")).group(1)) \
    if "timing" in obs else 0
check("F3.4 timing 观察层（指令级真值 ≥2 且字节级 ≥ 指令级）",
      "timing" in obs and n_rdtsc_real >= 2 and n_rdtsc_bytes >= n_rdtsc_real,
      "objdump 指令级 rdtsc ×%d | binowl 字节级 ×%d（观察层）" % (n_rdtsc_real, n_rdtsc_bytes))

# 5) int3-check：objdump -d 中 cmp $0xcc 指令存在（观察层）
n_cc_real = len(re.findall(r"cmp.*\$0xcc", dis))
check("F3.5 int3-check 观察层（objdump 指令级 cmp $0xcc ≥1）",
      "int3-check" in obs and n_cc_real >= 1,
      "objdump cmp $0xcc ×%d | binowl: %s" % (n_cc_real, obs.get("int3-check", {}).get("evidence")))

# 6) 负样本三方复核：bin_ls 字节级 0F31 vs 指令级（R43 根因证据固化）
ls = run(["objdump", "-d", os.path.join(FIX, "bin_ls.elf")])
ls_real = len(re.findall(r"\brdtsc\b", ls))
ls_ad = fingerprint.anti_debug_hints(os.path.join(FIX, "bin_ls.elf"))
check("F3.6 bin_ls R43 实证：指令级 0 但字节级命中 → timing 必须在观察层",
      ls_real == 0 and "timing" not in {f["family"] for f in ls_ad["findings"]}
      and "timing" in {o["family"] for o in ls_ad["observations"]},
      "objdump 指令级 rdtsc ×%d | binowl: findings=%s observations=%s" %
      (ls_real, [f["family"] for f in ls_ad["findings"]],
       [o["family"] for o in ls_ad["observations"]]))

# 7) 静态归属证据：fp_static 无 PT_INTERP 且 LD_PRELOAD 字符串真实存在
st = run(["readelf", "-l", os.path.join(FIX, "fp_static")])
no_interp = "INTERP" not in st
st_str = run(["strings", os.path.join(FIX, "fp_static")])
has_ldp = "LD_PRELOAD" in st_str.split()
st_ad = fingerprint.anti_debug_hints(os.path.join(FIX, "fp_static"))
env_in_obs = "env-check" in {o["family"] for o in st_ad["observations"]}
check("F3.7 静态链接 env 降级（无 INTERP ∧ 字符串真在 → 观察层）",
      no_interp and has_ldp and env_in_obs,
      "PT_INTERP 无=%s, LD_PRELOAD 在=%s, binowl env-check 层=%s" %
      (no_interp, has_ldp, "observations" if env_in_obs else "findings/无"))

n_pass = sum(1 for _, ok, _ in results if ok)
print("\n== F3 三方交叉验证: %d/%d PASS ==" % (n_pass, len(results)))
sys.exit(0 if n_pass == len(results) else 1)
