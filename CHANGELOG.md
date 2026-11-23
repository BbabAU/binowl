# Changelog

All notable changes to binowl are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`binowl map <file> [--to-offset ADDR]...`** — static memory-map view.
  ELF: every `PT_LOAD` with its file-backed range, zero-fill tail (`.bss`),
  page range and page-level overlaps. PE: header region and every section
  (`VA = ImageBase + RVA`, padding tail beyond `VirtualSize` flagged), with a
  default-layout (non-ASLR) image base. `--to-offset` translates one or more
  virtual addresses to file offsets; `<no file backing>` is reported for
  zero-filled or unmapped addresses instead of a made-up offset.
- New module `binowl.map` (`elf_memory_map`, `elf_vaddr_to_offset`,
  `pe_memory_map`, `pe_rva_to_offset`).
- `elf.parse()` program-header tuples now carry `p_memsz` as a 6th field.

### Fixed
- `pe.rva_to_raw()` — also consumed by the export parser:
  - RVAs inside the header region `[0, SizeOfHeaders)` now map 1:1 to the
    file instead of returning `None`.
  - RVAs in a section's zero-filled virtual tail
    `[VA + RawSize, VA + VSize)` now return `None`. Previously the function
    returned an offset **past the section's raw data** (confirmed on real
    samples: offsets ≥ `PointerToRawData + SizeOfRawData`). Export output on
    all fixtures is unchanged.

### Changed
- **`elf.parse()["phdrs"]` tuples grew from 5 to 6 fields** (`p_memsz`
  appended). Code that unpacks them positionally must be updated.

### Notes
- Divergence from `pefile.get_offset_from_rva`, measured point by point:
  file-backed and padding-tail addresses agree; for a section's zero-filled
  virtual tail `pefile` returns an offset past the section's raw data while
  binowl reports `<no file backing>`; addresses in gaps that no section
  covers (binowl: `<no file backing>`, `pefile`: identity mapping) are a
  documented gray zone — a `limitations` entry is planned.
- Regression suite 130 → 181 assertions; on the public clone 164 pass and
  the sample-dependent remainder skips with explicit reasons.
- Naming caveat: the MCP tool `binowl_map` lists segments/sections, whereas
  the CLI `binowl map` prints the file-backed/zero-fill view. Reconciling the
  two is planned for the next minor release.

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
