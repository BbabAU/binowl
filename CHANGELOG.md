# Changelog

All notable changes to binowl are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-22

### Added
- **`limitations` protocol** on `binowl_info` and `binowl_map`: every MCP payload
  now carries a structured list of what the result does *not* claim —
  `{code, detail}` entries for stripped binaries, packed samples (no section
  table), static binaries, missing Rich header, and byte-level-only anti-debug
  observations. The key is always present; an empty list means no caveats.
  Agents can reason about confidence, not just parse output.
- **Agent integration guide** in README (Claude Code one-liner +
  Cursor/Codex `mcp.json` snippet).

## [0.1.0] - 2026-11-22

### Added
- Hand-rolled **ELF parsing** (pure Python, no `pyelftools`): headers, section
  table, program headers, dynamic info, symbols, relocations.
- **checksec**: NX / RELRO / PIE / W+X segment audit for ELF targets.
- Hand-rolled **PE parsing**: headers, sections, imports, exports, and the
  doubly-anchored **Rich header** decode (build-tool fingerprint).
- **Packer & compiler fingerprints**: UPX ($Sign section layout + `UPX!`
  magic), MSVC family hints — every judgement spells out its evidence and
  honestly reports `unknown` / `n/a` instead of guessing.
- **`anti_debug_hints`**: byte-level static hints for five common anti-debug /
  anti-analysis API families, with explicit confidence tiers.
- **Three interfaces**: `binowl <file>` one-shot triage (auto ELF/PE
  detection, `--format` override, semantic exit codes 0/2/3), `binowl fp`
  fingerprinting, and `binowl mcp` — an MCP-stdio server exposing
  `binowl_info` / `binowl_map` for agent workflows.
- **Engineering**: 130-assertion regression suite cross-validated against
  `readelf` / `objdump` / `pefile`; GitHub Actions CI matrix (Python 3.9 +
  3.12); 14 self-constructed fixtures with regeneration scripts and a
  provenance manifest (system/third-party binaries excluded from
  redistribution; related tests skip with reason).

### Notes
- Formerly **rekit** — renamed to `binowl` after a name collision on both
  PyPI and GitHub. Same codebase, same history.
