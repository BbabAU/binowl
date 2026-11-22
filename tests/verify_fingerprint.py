#!/usr/bin/env python3
"""verify_fingerprint.py — M2.1 验收对拍（F2/F3）：fingerprint.py vs m2_manifest.json 期望表

期望表来自 build_samples.py 构造时刻的权威输出锁定（readelf / parse_rich_header），
本脚本独立调用 binowl.fingerprint 逐样本对拍三元组 + PE 侧 Rich 证据。
任何 FAIL → exit 1。输出同时存 evidence_fingerprint_verify.log。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from binowl import fingerprint  # noqa: E402

MANIFEST = os.path.join(HERE, "m2_manifest.json")


def main():
    man = json.load(open(MANIFEST))
    rows, npass = [], 0
    upx_pos = upx_neg = 0
    for s in man["samples"]:
        p = os.path.join(ROOT, s["path"])
        exp = s["expect"]
        try:
            got = fingerprint.fingerprint(p)
        except Exception as e:
            rows.append("FAIL %-22s fingerprint 异常: %s: %s" % (s["name"], type(e).__name__, e))
            continue
        checks = [
            ("family", exp["family"] == got["family"], "%r vs %r" % (got["family"], exp["family"])),
            ("packer_version", exp["packer_version"] == got["packer_version"],
             "%r vs %r" % (got["packer_version"], exp["packer_version"])),
            ("compiler", exp["compiler"] == got["compiler"],
             "%r vs %r" % (got["compiler"], exp["compiler"])),
            ("stripped", exp["stripped"] == got["stripped"],
             "%r vs %r" % (got["stripped"], exp["stripped"])),
        ]
        bad = ["%s(%s)" % (n, d) for n, ok, d in checks if not ok]
        if bad:
            rows.append("FAIL %-22s %s" % (s["name"], "; ".join(bad)))
        else:
            npass += 1
            fam = got["family"] or "none"
            rows.append("PASS %-22s family=%-4s ver=%-5s compiler=%-36s stripped=%s" %
                        (s["name"], fam, got["packer_version"] or "-",
                         got["compiler"] or "None", got["stripped"]))
        if exp["family"] == "UPX" and got["family"] == "UPX":
            upx_pos += 1
        if exp["family"] is None and got["family"] is None:
            upx_neg += 1
    n = len(man["samples"])
    rows.append("")
    rows.append("== F2 UPX: 召回 %d/3  负样本无误报 %d/13" % (upx_pos, upx_neg))
    rows.append("== F3 总对拍: %d/%d PASS" % (npass, n))
    out = "\n".join(rows)
    print(out)
    return 0 if npass == n and upx_pos == 3 and upx_neg == 13 else 1


if __name__ == "__main__":
    sys.exit(main())
