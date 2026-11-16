# MindLoom

[English](README.md) | [简体中文](README.zh-CN.md)

**MindLoom** 将 **Codex**、**Antigravity**、**DSH** 等多端 AI Agent 编程对话**编织**为本地原生、可溯源、可验证的 **Obsidian 知识记忆库**，内置双目录隐私隔离、Mode 0 零出站检索、原子硬链接发布与轻量全功能伴侣控制台插件。

---

## 核心架构亮点

```
┌──────────────────────────────────┐       ┌──────────────────────────────────┐
│   Obsidian Vault（人类可读区）    │       │  MindLoom-Data（隔离运行态区）    │
│  ~/Documents/Obsidian/MindLoom   │       │  ~/Documents/Obsidian/MindLoom-  │
│                                  │       │  Data                            │
│  ├── 首页.md                     │       │  ├── raw/{codex,antigravity,dsh} │
│  ├── 00_MOC/                     │◄─link─┤  ├── staging/ (wx 独占暂存)       │
│  ├── 10_Readable_Sessions/       │       │  ├── runtime/state.sqlite        │
│  ├── 20_Evidence_Cards/          │       │  ├── runtime/revisions/          │
│  ├── 30_Knowledge_Notes/         │       │  ├── manifests/project-map.json  │
│  ├── 40_Review_Queue/ (PROP-*)   │       │  ├── egress/ (脱敏外发包)        │
│  ├── 50_Bases_Views/ (*.base)    │       │  └── cli/ (独立部署运行时)        │
│  └── .obsidian/plugins/mindloom/ │──CLI──►                                  │
└──────────────────────────────────┘       └──────────────────────────────────┘
```

- **默认零出站检索（Mode 0）**：`mem search --mode literal` 100% 离线执行。标记为 `privacy: local_only` 或缺失合法 `privacy` 的笔记永不进入检索返回、`00_MOC/` 地图与外部导出。
- **原文 `^event-` 锚点溯源**：每篇可读会话为事件生成稳定 `^event-NNNNNN` 块锚点，支持从知识笔记与证据卡一键直达原始上下文。
- **只增不改提案与双版本防覆盖（`PROP-*`）**：知识修订以独立提案写入 `40_Review_Queue/`，通过前后置条件与双版本 SHA-256 哈希绑定核验（`mem reconcile`）。
- **原子发布与三端定时调度**：同卷硬链接原子落盘（跨卷 `EXDEV` 安全回退）、`write.lock` 并发保护，以及原生 Windows Task Scheduler / macOS `launchd` / Linux `systemd --user` & `crontab` 调度支持。
- **Obsidian 全量控制台伴侣插件（`plugin/`）**：约 30 KB 零膨胀打包，所有读写严格经由普通权限 `mem` CLI 执行：
  - Mode 0 快速记忆检索弹窗，回车直达笔记与 `#^event-NNNNNN` 锚点
  - 提案 Diff 预览与 `mem reconcile` 核对工作台
  - 单篇墓碑与历史版本恢复面板（先 Diff 预览，二次确认后原子恢复）
  - 可视化 `project-map.json` 白名单编辑器（含路径冲突校验）
  - 只读云端预算看板 + 一键复制管理员终端命令引导器

---

## 1 分钟快速上手

### 环境要求
- **Node.js 22 LTS（`>= 22.15.0`）或 Node.js 24+ LTS**（使用内置 `node:sqlite` 与自 22.15.0 起提供的 `node:zlib` Zstd；若使用 23.x 需 `>= 23.8.0`）
- **Git**
- **Obsidian 桌面端**（可选，用于浏览 Bases 视图与伴侣插件控制台）

### 一键初始化

```bash
git clone https://github.com/TttXxx36/MindLoom.git
cd MindLoom

# 一键完成环境自检 -> 建双库 -> 扫描本机项目生成白名单 -> 注入 Obsidian 伴侣插件
node cli/mem.mjs setup --yes
```

或使用各平台一键引导脚本：

- **Windows (PowerShell)**：
  ```powershell
  pwsh -File .\scripts\install.ps1 -Yes
  # 在人类交互终端可选一键签发 30 天白名单自动同步票据并注册定时任务：
  pwsh -File .\scripts\install.ps1 -AuthorizeAutoSync
  ```
- **macOS / Linux (Bash)**：
  ```bash
  bash ./scripts/install.sh --yes
  # 在人类交互终端可选一键签发 30 天白名单自动同步票据并注册定时任务：
  bash ./scripts/install.sh --authorize-autosync
  ```

### 自定义双目录路径与隔离试用

```bash
node cli/mem.mjs setup --vault "/path/to/MyVault" --data "/path/to/MyVault-Data" --yes
```

> **首次安装门禁与隔离试用说明：**
> - **首次安装仅承诺空库**：初次运行 `setup` / `init` 仅用于初始化空 Vault 与空 Data 目录；若将已存在内容的 Obsidian 库配对全新的 Data 目录，系统会按防覆盖门禁返回 `INIT_ALREADY_INITIALIZED` 拒绝写入。
> - **试用请隔离配置与会话源**：`--vault` 和 `--data` 仅切换库目录，仍会通过 `writeInstallConfig` 更新默认用户配置（`~/.mindloom/config.json`）。若要进行沙盒试用而不影响默认配置或真实会话目录，请在当前测试进程设置 `MINDLOOM_CONFIG`（并按需指定模拟会话源 `MINDLOOM_CODEX_HOME`、`MINDLOOM_ANTIGRAVITY_BRAIN_DIR`、`MINDLOOM_DSH_HOME`）：
>   ```powershell
>   $env:MINDLOOM_CONFIG = "$env:TEMP\ml-trial-config.json"
>   $env:MINDLOOM_ANTIGRAVITY_BRAIN_DIR = "$env:TEMP\mock-agy-brain"
>   node cli/mem.mjs setup --vault "$env:TEMP\TrialVault" --data "$env:TEMP\TrialVault-Data" --yes
>   ```

随后在 **Obsidian** 中打开该 Vault 目录即可使用；伴侣插件已安全合并至 `.obsidian/community-plugins.json`，绝不覆盖您原有的其他插件。

---

## 安全隐私边界（三路隔离）

1. **普通宿主 / Agent 终端 (`cli/mem.mjs`)**：仅执行离线 Mode 0 检索、`reconcile`、`restore`、`render-moc` 与 `distill --dry-run`；Agent/非交互环境强制触发 `EXIT 43` 拦截自签授权。
2. **Obsidian 伴侣插件 (`plugin/`)**：严格通过 `CliBridge` 调用普通 CLI，**绝不**读取 API Key 文件、**绝不**直连或修改 `operator-state.sqlite`、**绝不**伪造 `trustedHumanContext`。
3. **提权管理员终端 (`cli/mem-operator.mjs` + `scripts/setup-operator-isolation.ps1`)**：Windows 下通过 `SYSTEM` + `BUILTIN\Administrators` NTFS ACL 硬隔离保护 API Key 与 `operator-state.sqlite`，仅在您主动运行实网 `distill` 或受控评测时启用。

---

## 常用 CLI 命令

```bash
node cli/mem.mjs doctor --json                      # 检查 Node、SQLite、Zstd 与硬链接
node cli/mem.mjs status --json                      # 查看笔记总数、待审提案与同步状态
node cli/mem.mjs list-sessions --limit 20           # 扫描 Codex / Antigravity / DSH 会话
node cli/mem.mjs auto-sync --dry-run --json         # 预览白名单增量同步候选
node cli/mem.mjs render-moc --update-digests        # 重建 00_MOC/ 与学习简报
node cli/mem.mjs search "401" --mode literal        # Mode 0 离线精确检索
node cli/mem.mjs reconcile                          # 同步改名/缺失并核对提案
node cli/mem.mjs restore <ID> --revision rev-0001   # 预览或追加 --confirm 原子恢复
node cli/mem.mjs backup --target /path/to/backups   # WAL 检查点一致备份
```

---

## 常见排障

- **提示 `Node >= 22.15.0` 或 `node:sqlite` / Zstd 不可用**：请升级至 Node.js v22.15.0+ LTS 或 v24+ LTS（v23 需 >= 23.8.0）。
- **提示 `ERR_VAULT_DATA_NESTED`**：`Vault` 与 `Data` 必须为同级分离目录（如 `MindLoom` 与 `MindLoom-Data`），禁止相互嵌套。
- **返回 `ACCESS_DENIED (EXIT 43)`**：安全门禁设计如此——所有授权签发命令（`setup --authorize-autosync`、`approve-ingest-human.ps1`、`approve-human.ps1`）禁止在 AI Agent 或非交互终端运行，请您在个人终端亲自执行。
- **插件状态栏提示 `CLI offline`**：打开 **设置 -> MindLoom** 检查 Data 目录与 Node 路径，点击 **Run mem doctor** 验证。

---

## 开源协议

[MIT](LICENSE)
