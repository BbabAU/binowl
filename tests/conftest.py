# tests/conftest.py — 分发边界共享判定（O3 建仓引入，2026-11-22）
# CHARTER #4：系统二进制不得随包分发；第三方捆绑物来源登记后方可分发。
# 本地开发环境（17 样本）全量跑；公开克隆/CI 环境（14 样本）对缺失样本自动 skip，
# 理由明示，不静默——M2.5d 审计完成后以替代样本恢复全量。
import os

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def has_sample(name):
    return os.path.exists(os.path.join(FIX, name))


SKIP_BIN_LS = None  # 已解除（M2.5d：bin_ls.elf → 自构造 dyn_ls 替代，锚点重定标完成）

SKIP_CLI = ("cli-64.exe / cli64_upx.exe excluded from repo (M2.5d decision b): "
            "setuptools-wheel bundled launcher + UPX derivative, provenance "
            "registered in manifest; self-built MSVC replacement queued (O1 batch)")
