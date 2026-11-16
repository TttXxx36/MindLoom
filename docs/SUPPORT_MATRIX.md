# MindLoom Support Matrix & Operational Boundaries

MindLoom is designed as a **single-user, local-first, zero-outbound-by-default** Agent × Obsidian memory workspace. This document defines the supported tiers, source-of-truth hierarchy, and lifecycle semantics ("withdrawal vs purge").

---

## 1. Support & Isolation Matrix

| Feature Tier | Windows | macOS | Linux | Enforcement / Guarantee Level |
| --- | --- | --- | --- | --- |
| **Mode 0 Local Memory & Vault** (`mem setup`, `auto-sync`, `render-moc`, `search --mode literal`, Companion Plugin) | Supported | Supported | Supported | **Logical data partitioning** (`Vault/` vs `Vault-Data/`), per-instance scheduler naming, paired SHA-256 identity binding (`instance-identity.json`), and `EXIT 43` interactive terminal checks. *Not OS kernel sandboxing.* |
| **Strongly Isolated Confidential Ingest** (`--sensitivity confidential`) | Supported | Supported | Supported | Enforces strict three-way `isolation-sentinel.mjs` checks before allowing non-sanitized confidential ingest; falls back to `degraded_low_sensitivity_only` when the agent process can still read `raw/`. |
| **Optional Cloud Distill / Rerank (`mem-operator.mjs`)** | **Primary** (NTFS Admin ACL via `setup-operator-isolation.ps1`) | Experimental (Unix owner chmod boundary) | Experimental (Unix owner chmod boundary) | Requires separate elevated Admin Operator CLI + `CEGR-*` human approval ticket + `operator-state.sqlite` budget ledger. Windows NTFS `BUILTIN\Administrators` + `SYSTEM` ACL provides real OS read/write barrier against unprivileged CLI/plugin. |
| **Whole-Vault Backup & Takeover (`mem backup`, `mem restore-backup`, `mem use`)** | Supported | Supported | Supported | Creates SHA-256 + SQLite `VACUUM INTO` backups, rebinds instance manifests & companion plugin config cleanly inside restored copies, rotates instance identity + locks restored cloud approvals, and leaves host `~/.mindloom/config.json` untouched unless `--switch` or `mem use` is explicitly invoked. |

---

## 2. Source-of-Truth Hierarchy

| Layer | Role | Authoritative For | Rebuildable? |
| --- | --- | --- | --- |
| **Obsidian Vault Markdown** (`10_Readable_Sessions/`, `20_Evidence_Cards/`, `30_Knowledge_Notes/`, `40_Review_Queue/`) | Human-readable & editable records |正文 content, readable titles, explicit `sources` links, proposal `pre_conditions`/`post_conditions` | No (user edits preserved) |
| **SQLite Ledger** (`Data/runtime/state.sqlite`) | Operational authority | Note registration (`notes`), atomic publish state (`publish_intents`), one-way `local_only` privacy lock, proposal double-hash bindings (`reconcile_states`), cross-snapshot tombstones (`tombstones`), ingest/egress approvals | No (backed up via `VACUUM INTO`) |
| **Immutable Raw Snapshots** (`Data/raw/`, `Data/manifests/`) | Evidentiary source of truth | Raw compressed session archives, byte offsets (`^event-`), `sanitizer_version` / `parser_version` provenance | No |
| **Derived Outputs** (`00_MOC/`, `首页.md`, `Data/runtime/index/`, `Data/runtime/vectors.sqlite`) | Fast navigation & search | Project MOC maps, human digests, lexical/hybrid indexes (`<!-- mindloom-generated: ... -->`) | Yes (safely regenerated or withdrawn) |
| **Local Vault `.git`** | Audit history | Local-only historical commits (`git remote` strictly forbidden) | History log only (never online state judge) |

---

## 3. Withdrawal vs. Full Purge Semantics

- **Withdrawal (`mem delete <id> --confirm` / privacy downgrade to `local_only` / `mem render-moc`)**:
  - Deletes the formal Markdown file from the Vault, marks `notes.status = 'deleted'` (and monotonically locks privacy to `local_only`), writes a cross-snapshot `tombstones` suppression entry, removes stale MindLoom-generated `00_MOC/<Project>.md` pages (while preserving handwritten files in `00_MOC/`), and excludes the item from Mode 0/1/2 search, MOCs, and external egress.
  - Preserves `Data/raw/` session archives, `Data/runtime/revisions/`, local Git history, and previously written external backups so accidental deletions remain recoverable (`mem restore`).
- **Full Purge (Physical Erasure)**:
  - Not performed automatically by `mem delete`. Permanently purging sensitive content requires manually removing the relevant archive files from `Data/raw/`, `Data/runtime/revisions/`, external backup sets, and rewriting/reinitializing Vault `.git` history.

---

## 4. Production Acceptance Checklist (Real Host)

Before promoting a release beyond beta/prerelease, run synthetic end-to-end verification on real desktop hosts:
1. Real Obsidian client opens Vault -> Companion plugin executes Search (`Mode 0`), Proposal diff, Tombstone preview/restore, Whitelist editor, and read-only Budget viewer.
2. Sleep/wake test on Windows Task Scheduler (`schtasks`), macOS `launchd`, and Linux `systemd`/`crontab`.
3. Crash-recovery drill: simulate `files_published` without `notes` row -> `mem doctor` flags `pending_recovery` -> `mem recover-publish` reconciles cleanly without overwriting user edits.
4. Disaster recovery drill: `mem backup --target ...` -> `mem restore-backup --backup ... --vault <new> --data <new> --self-check <query>` -> verify old default untouched -> `mem use --vault <new> --data <new>` -> confirm CLI + Obsidian companion plugin follow the activated instance.
