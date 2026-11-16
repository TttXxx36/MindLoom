# MindLoom

[English](README.md) | [简体中文](README.zh-CN.md)

**MindLoom** weaves multi-agent coding sessions (**Codex**, **Antigravity**, **DSH**) into a **local-first, verifiable Obsidian knowledge vault** with strict dual-directory privacy isolation, deterministic Mode 0 retrieval, atomic hardlink publishing, and a lightweight companion console plugin.

---

## Architecture Highlights

```
┌──────────────────────────────────┐       ┌──────────────────────────────────┐
│   Obsidian Vault (Human-Read)    │       │  MindLoom-Data (Isolated State)  │
│  ~/Documents/Obsidian/MindLoom   │       │  ~/Documents/Obsidian/MindLoom-  │
│                                  │       │  Data                            │
│  ├── 首页.md                     │       │  ├── raw/{codex,antigravity,dsh} │
│  ├── 00_MOC/                     │◄─link─┤  ├── staging/ (wx exclusive)     │
│  ├── 10_Readable_Sessions/       │       │  ├── runtime/state.sqlite        │
│  ├── 20_Evidence_Cards/          │       │  ├── runtime/revisions/          │
│  ├── 30_Knowledge_Notes/         │       │  ├── manifests/project-map.json  │
│  ├── 40_Review_Queue/ (PROP-*)   │       │  ├── egress/ (sanitized pkgs)    │
│  ├── 50_Bases_Views/ (*.base)    │       │  └── cli/ (deployed runtime)     │
│  └── .obsidian/plugins/mindloom/ │──CLI──►                                  │
└──────────────────────────────────┘       └──────────────────────────────────┘
```

- **Zero-Egress Default (Mode 0)**: `mem search --mode literal` is 100% offline. Notes marked `privacy: local_only` or missing valid `privacy` frontmatter never enter search outputs, `00_MOC/` maps, or external exports.
- **Lineage & `^event-` Anchors**: Every readable session assigns deterministic `^event-NNNNNN` block anchors, linked from `20_Evidence_Cards/` and `30_Knowledge_Notes/`.
- **Safe Proposal & Version Binding (`PROP-*`)**: Updates are staged as non-destructive proposals in `40_Review_Queue/`, checked with pre/post conditions and dual SHA-256 hashes (`mem reconcile`).
- **Atomic Publish + Cross-Platform Scheduler**: Same-volume hardlink publishing (`fs.linkSync` with `EXDEV` safe fallback), write-lock coordination, and native Task Scheduler (Windows) / `launchd` (macOS) / `systemd --user` & `crontab` (Linux).
- **Companion Obsidian Plugin (`plugin/`)**: ~30 KB zero-bloat bundle communicating strictly through the unprivileged `mem` CLI (`CliBridge`):
  - Quick Search Modal (Mode 0) with direct jump to notes and `^event-NNNNNN` anchors
  - Proposal Diff & `mem reconcile` workbench
  - Tombstone & Version Restore panel with explicit confirmation modal
  - Visual `project-map.json` whitelist editor with collision validation
  - Read-only cloud budget viewer + copy-ready Administrator terminal command guide

---

## 1-Minute QuickStart

### Prerequisites
- **Node.js >= 22** (required for built-in `node:sqlite` and `node:zlib` Zstd)
- **Git**
- **Obsidian Desktop** (optional for GUI console & Bases views)

### Option A: Interactive / One-Command Setup

```bash
git clone https://github.com/TttXxx36/MindLoom.git
cd MindLoom

# Full automatic setup (preflight -> dual dirs -> discover workspaces -> inject plugin)
node cli/mem.mjs setup --yes
```

Or use the platform wrapper scripts:

- **Windows (PowerShell)**:
  ```powershell
  pwsh -File .\scripts\install.ps1 -Yes
  # Optional interactive human terminal authorization for 30-day whitelist auto-sync:
  pwsh -File .\scripts\install.ps1 -AuthorizeAutoSync
  ```
- **macOS / Linux (Bash)**:
  ```bash
  bash ./scripts/install.sh --yes
  # Optional interactive human terminal authorization for 30-day whitelist auto-sync:
  bash ./scripts/install.sh --authorize-autosync
  ```

### Option B: Custom Vault / Data Paths

```bash
node cli/mem.mjs setup --vault "/path/to/MyVault" --data "/path/to/MyVault-Data" --yes
```

Then open the Vault folder in **Obsidian Desktop** and enable community plugins if prompted — `mindloom` is already installed and pre-registered in `.obsidian/community-plugins.json` without overwriting any of your existing plugins.

---

## Security & Three-Way Boundary Model

1. **Ordinary Host / Agent Terminal (`cli/mem.mjs`)**:
   - Mode 0 literal search, `reconcile`, `restore`, `render-moc`, `distill --dry-run`.
   - Cannot self-issue `approved_low_sensitivity` ingest approvals (`EXIT 43` in agent/non-TTY contexts) and cannot issue or spend `CEGR-*` cloud budgets.
2. **Obsidian Companion Plugin (`plugin/`)**:
   - Runs commands exclusively through `CliBridge` (`node <DataDir>/cli/mem.mjs ... --json`).
   - **Never** reads API key files, **never** opens or mutates `operator-state.sqlite`, and **never** spoofs `trustedHumanContext`.
3. **Privileged Admin Operator (`cli/mem-operator.mjs` + `scripts/setup-operator-isolation.ps1`)**:
   - On Windows, isolates API keys and `operator-state.sqlite` under `SYSTEM` + `BUILTIN\Administrators` NTFS ACLs.
   - Required only for optional live cloud `distill` or `emrank` embedding trials.

---

## Common CLI Commands

```bash
node cli/mem.mjs doctor --json                      # Environment & hardlink check
node cli/mem.mjs status --json                      # Vault/Data health & pending proposals
node cli/mem.mjs list-sessions --limit 20           # Discover Codex/Antigravity/DSH sessions
node cli/mem.mjs auto-sync --dry-run --json         # Preview whitelist sync candidates
node cli/mem.mjs render-moc --update-digests        # Rebuild 00_MOC/ & Digest Brief
node cli/mem.mjs search "401" --mode literal        # Offline Mode 0 search
node cli/mem.mjs reconcile                          # Sync renames/missing & verify proposals
node cli/mem.mjs restore <ID> --revision rev-0001   # Preview or --confirm atomic restore
node cli/mem.mjs backup --target /path/to/backups   # Consistent WAL-checkpointed backup
```

---

## Troubleshooting

- **`Node >= 22` / `node:sqlite` error**: Upgrade Node.js to v22 LTS or v24+.
- **`ERR_VAULT_DATA_NESTED`**: `Vault` and `Data` directories must be separate siblings (e.g., `MindLoom` and `MindLoom-Data`), never nested inside each other.
- **`ACCESS_DENIED (EXIT 43)`**: Human approval commands (`setup --authorize-autosync`, `approve-ingest-human.ps1`, `approve-human.ps1`) intentionally reject AI agent shells (`ANTIGRAVITY_AGENT`, `CODEX_SANDBOX`, `CI`, non-TTY). Run them directly in your own terminal.
- **Plugin says `CLI offline`**: Open **Settings -> MindLoom** and verify **Data Directory Path**, **Node.js Executable**, and click **Run mem doctor**.

---

## License

[MIT](LICENSE)
