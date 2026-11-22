# rekit — 自研逆向分析工具包 · 项目章程

> 长期项目 #1（2026-11-07 立项）。前身：2026-11-06 白银任务 mini_elf.py。
> **2026-11-17 定位升级（用户指令）**：交付目标从"自用"升级为"可给别人用、开源推广"——
> 每一行代码从此按"陌生人拿到就能跑"的标准写。

## 为什么是这个项目（价值声明）

- **潜力**：逆向大神的标志性资产不是"会用工具"，而是"有自己顺手的工具"。rekit 把每天学到的东西固化为可复用的代码资产，长期复利。
- **价值**：从 0 到 1 构建分析工具链（解析→指纹→加载→CFG→反编译），每一层都加深对底层的理解，比纯看文章深一个数量级。
- **AI 成长价值**：工程能力 × 领域知识双螺旋；每日实操任务的产出天然汇入本项目，日报闭环与长期项目合流，不增加并行负担。
- **开源交付价值（2026-11-17 新增）**：净室指纹判据 + 权威工具交叉验证 + 常绿测试套件，
  是市场上少见的"判据可解释、结果可复核"的轻量分析工具路线——这正是开源推广的差异化卖点。

## 开源交付标准（2026-11-17 新增，M2 收口前达成）

新里程碑 **M2.5 packaging（开源化改造）**，完成标准：
1. **可安装**：pyproject.toml（PEP 621）+ console_scripts 入口 `rekit`，干净虚拟环境 `pip install .` 一次成功
2. **可上手**：README.md（双语或英文优先）——安装/快速上手/输出示例/判据说明/与 readelf·pefile 对拍方法；LICENSE（MIT）
3. **可持续**：GitHub Actions CI（pytest 矩阵 ≥2 Python 版本）；语义化版本 + 面向用户的 CHANGELOG
4. **可分发**：fixtures 样本许可证审计——系统二进制（bin_ls.elf）不得随包分发，改用自构造样本替代并保留对拍能力；全部自有样本带来源登记（manifest 已具备）
5. **代码质量**：公开 API docstring 全覆盖；`rekit` 名称 GitHub 撞名检查 + 必要时更名决策

> **进度（2026-11-22）**：M2.5 五刀已落四——a「可安装」✅ 11-18（G1–G5 21/21 零返工）/ e' 全量更名 ✅ 11-20（R1–R6 全 PASS）
> / b「README+LICENSE」✅ 11-21（G1–G5 全 PASS，G4 抓 readme 声明缺口返工 1 次修复）/ **c「CI」✅ 11-22
> （C1–C5 全 PASS：.github/workflows/ci.yml 双触发 matrix 3.9+3.12；C3 净室实测抓出 pefile 对拍缺口 →
> 纳入 dev extras，123 断言 CI 全绿；vermin 最低 3.4；徽章 OWNER-PLACEHOLDER 占位；证据
> artifacts/2026-11-22/）**；余 d「fixtures 许可审计」。**O2 已闭环（2026-11-19 用户授权定案）**：对外名
> **binowl**（binwalk 谱系 + owl「看透黑暗」；PyPI/GitHub 双端实测最净，证据
> artifacts/2026-11-19/naming_check.log）；import/dist/CLI/MCP 工具名统一为 binowl，工程根
> 目录 learning/rekit/ 不变（cron 路径兼容），历史文档 rekit = 曾用名；重命名执行 =
> M2.5e'（TASK_m25e_rename.md，标准 R1–R6 预写锁死）已 ✅。**O3 已闭环（2026-11-22 用户「建仓」授权）**：
> https://github.com/BbabAU/binowl public，main @ Initial release v0.1.0（47 文件）；CI 双矩阵 3.9+3.12
> run#10 全绿、README 徽章 passing 挂真链。**M2.5d ✅（同日续跑）**：ELF 锚点样本 bin_ls.elf → 自构造
> dyn_ls（distro 风格 PIE，readelf 双端快照重定标），bin_ls 系 skip 全解除（克隆 88+31s→114+8s，
> readelf 对拍 CI 首跑），cli 系决策 b 排除+manifest provenance 登记；**M2.5 五刀（a/e'/b/c/d）全部
> 收官，本地 125 断言常绿，CI 双矩阵全绿**。**v0.2.0 已发布（2026-11-22）**：limitations 协议
> （MCP 载荷恒含结论边界声明，REA 纪律吸收）+ agent 接入指南 + GitHub Release
> （github.com/BbabAU/binowl/releases/tag/v0.2.0）；130 断言常绿。

## 长期目标（v1.0，对齐 ROADMAP 三阶段）

`rekit info <file>` 一条命令输出二进制分诊报告：格式/架构/入口/保护（壳/加固）/编译器指纹/导入导出概要；
`rekit map <file>` 输出内存映射视图；后续扩展 CFG 与调用图。**全程纯 Python 手解 + 与权威工具交叉验证。**

## 里程碑（计划步骤）

| 里程碑 | 内容 | 完成标准（验收） |
|---|---|---|
| M1 loader ✅ 2026-11-14 收口 | elf.py（头/段/节/动态段/符号表/重定位/checksec 四态）+ pe.py（头/节/导入/导出/Rich）+ 统一 cli.py（ELF/PE magic 自动识别，`python3 -m rekit.cli <file>`） | **回归测试套件常绿**（pytest 全过，58 断言/2026-11-14 实测）；10 样本 fixtures 覆盖 PIE/非 PIE/静态/norelro/execstack/PE(EXE·DLL·富Rich·伪Rich)/系统二进制（对账证据：artifacts/2026-11-14/M1_CLOSEOUT_AUDIT.md） |
| M1.5 MCP ✅ 2026-11-15 | `rekit mcp` 本地服务器，info/map 包装为 MCP 工具（CLI+MCP 双身份） | cron 日报的自我验收环节实际调用 rekit 工具完成一次交叉验证 ✅ 已达成：verify_mcp.py 独立 stdio 客户端 35/35 PASS（readelf/pefile 权威对拍）+ pytest 58→73 常绿（证据 artifacts/2026-11-15/） |
| M2 fingerprint（核心 ✅ + M2.5 开源化进行中） | UPX/壳识别、编译器指纹（Rich/MSVC family）、anti_debug_hints（净室观察法；判据 ≥2 独立证据组合——R33） | 识别率 100% 误报 0（17 样本全对拍，11-16/17/18 三连：UPX 3/3·Rich 11 对·anti_debug F1–F5）；**M2.5 开源化四刀 ✅**（a 可安装 11-18 / e' 更名 11-20 / b README·LICENSE 11-21 / c CI 11-22），余 d「fixtures 许可审计」见开源交付标准 |
| M3 map&patch | 内存映射视图、RVA↔offset 换算、IAT 修复雏形 | 换算对全部段 100% 正确（与手工计算+工具对照） |
| M4 cfg | 函数发现、CFG、调用图（x64） | 对 objdump 反汇编结果的覆盖率/一致率达标（数字届时定标） |
| M5 mini-decompiler | 表达式/控制流恢复（终极） | 小函数输出与人工阅读一致（抽样验收） |

## 每日任务量（2026-11-07 依基线数据定标，详见 PROGRESS.md）

实测基线：扩展型白银 1–2 min / 从零型白银 5–8 min / 返工集中于从零型。
- 每日实操任务 = 1 个白银（优先 rekit 下一子任务）+ 可选 1 个青铜热身
- 黄金任务拆为 ≤ 白银粒度子任务，逐日逐个独立验收
- 当日返工 ≥ 3 次 → 次日降档巩固；周五对照基线速度复盘，偏差超 2 天走变更流程

## 每日验收标准（长期项目部分，叠加在日报五件套之上）

1. 当日代码增量必须**可运行**：`python3 -m rekit.cli <file>` 或 pytest 通过
2. 交叉验证证据留存：与 readelf/objdump 输出的比对结果写入当日 artifacts
3. PROGRESS.md 回写一行：完成项 + 耗时 + 与基线速度的偏差
4. 严禁虚报；未达标项次日优先补课（不影响日报其余部分）

## 任务与验收标准的变更规则（仅长期项目有效，2026-11-07 用户授权）

- **允许**：发现问题（标准不合理/外部依赖变化）或优化算法后，自主修改任务要求与验收标准
- **纪律**（三条红线不可越）：
  1. 每次变更必须记入 TASKLOG.md（内部变更日志，不入公开仓库）：`日期 | 旧标准 → 新标准 | 原因 | 影响评估`，无日志的变更无效。仓库根的 `CHANGELOG.md` 是**面向用户**的版本变更日志（Keep a Changelog 格式），不承载内部条目
  2. 变更不得用于掩盖当日失败——失败照实记录，只能从次日起用新标准
  3. 标准只能更精确/更合理（可证伪性不降），不得降级为不可验证
- **不适用**：每日短期任务（巡检、知识点）仍执行"标准执行前写定、不许放宽"的硬规则

## 目录结构

```
learning/rekit/
├── CHARTER.md      # 本章程（公开）
├── README.md / LICENSE / pyproject.toml / .gitignore
│                   # 开源交付面（公开）
├── CHANGELOG.md    # 面向用户的版本变更日志（Keep a Changelog，公开）
├── PROGRESS.md     # 每日进度回写 + 速度基线数据（内部，不入库）
├── TASKLOG.md      # 任务/验收标准变更日志（内部，不入库；2026-11-23 前名为 CHANGELOG.md）
├── REKIT-PLAN.md   # 里程碑规划（内部，不入库）
├── binowl/         # 源码包：elf / pe / fingerprint / cli / mcp
└── tests/          # 交叉验证回归测试（fixtures 含再生脚本与 provenance 清单）
```
