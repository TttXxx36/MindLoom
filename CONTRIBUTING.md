# Contributing to MindLoom

Thank you for contributing to **MindLoom**!

## Development Requirements

- **Node.js 22 LTS (`>= 22.15.0`) or Node.js 24+ LTS** (required for built-in `node:sqlite` and `node:zlib` Zstd support; 23.x requires `>= 23.8.0`)
- **Git**
- **Obsidian Desktop** (optional, for testing the companion plugin UI)

## Local Setup & Verification

```bash
# Run full Node test suite
npm test

# Type-check and build the Obsidian companion plugin
npm run plugin:typecheck
npm run plugin:build

# Run privacy/secret/path leak scan (must report 0 findings)
npm run lint:leaks
```

## Engineering & Security Guidelines

1. **Zero Personal Data in Commits**: Never commit real local session `.jsonl` / `.zstd` files, SQLite databases, API keys, or personal filesystem paths.
2. **Test Fixtures**: Use synthetic test fixtures generated at runtime. Never hardcode continuous secret patterns (e.g., `sk-...`, `Bearer eyJ...`); assemble synthetic tokens dynamically in tests.
3. **Security Boundaries**:
   - Mode 0 (`literal`) search must remain 100% offline with zero network calls.
   - `plugin/` code must NEVER read API key files, mutate `operator-state.sqlite`, or spoof `trustedHumanContext`.
   - All privileged approvals (`EXIT 43` guards, `CEGR-*` cloud approvals) must stay isolated to interactive human terminals.
4. **Pull Requests**: Ensure `npm test`, `npm run plugin:typecheck`, `npm run plugin:build`, and `npm run lint:leaks` all pass before opening a PR.
