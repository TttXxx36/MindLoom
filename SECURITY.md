# Security Policy

## Local-First Privacy Guarantees

MindLoom is built around strict dual-directory isolation and privilege separation:

1. **Dual-Directory Separation**: Human-readable Markdown notes live in your Obsidian Vault (`MindLoom/`), while raw compressed snapshots, SQLite ledgers, staging buffers, and egress manifests live in an isolated sibling directory (`MindLoom-Data/`).
2. **Default Zero-Egress Retrieval (Mode 0)**: Literal search (`mem search --mode literal`) is 100% offline. Notes marked `privacy: local_only` or missing valid `privacy: sanitized` frontmatter are blocked from search output, MOC indexes, and external export.
3. **Human-Interactive Gate (`EXIT 43`)**: Automated agent environments (`ANTIGRAVITY_AGENT`, `CODEX_SANDBOX`, `CI`, non-TTY stdin) are explicitly blocked from self-issuing ingest or cloud egress approvals.
4. **Companion Plugin Isolation**: The Obsidian plugin executes operations exclusively through the unprivileged `mem` CLI and never reads API key files or `operator-state.sqlite`.
5. **Windows NTFS Operator Isolation**: Optional cloud distillation/embedding keys and `operator-state.sqlite` are protected with `SYSTEM` + `BUILTIN\Administrators` NTFS ACLs (`scripts/setup-operator-isolation.ps1`). For the full per-platform support matrix and withdrawal/purge boundaries, see [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, especially anything involving privacy leaks, approval-gate bypasses, or privilege escalation.

Instead, report vulnerabilities privately via GitHub Security Advisories on `TttXxx36/MindLoom` with:
- Affected component (`cli/`, `src/`, `scripts/`, or `plugin/`)
- Reproduction steps using **synthetic** data only (never attach real session logs or credentials)
- Expected vs. actual security boundary behavior
