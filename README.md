[![CI](https://github.com/BbabAU/binowl/actions/workflows/ci.yml/badge.svg)](https://github.com/BbabAU/binowl/actions/workflows/ci.yml)

# binowl

**Pure-Python binary triage toolkit** — hand-rolled ELF/PE parsing, checksec,
packer & compiler fingerprinting and anti-debug hints, with CLI and MCP-stdio
interfaces.

> Formerly **rekit** — renamed to `binowl` on 2026-11-20 after a name collision
> on both PyPI and GitHub. Same codebase, same history; see `CHANGELOG.md`.

## Why binowl?

Every judgement is explainable and reproducible:

- **Hand-rolled parsers** — no `pyelftools`, no `pefile`, no third-party
  runtime deps; ELF/PE structures are parsed field-by-field in pure Python.
- **Cross-checked against the authorities** — every fingerprint criterion is
  validated against `readelf` / `objdump` / `pefile` output (see
  [Cross-validation](#cross-validation-against-authoritative-tools)).
- **Explainable fingerprints** — packer/compiler detection is based on
  net-room observation (section names, doubly-anchored Rich header, block-level
  median entropy, debug-API families), and honestly reports `unknown` /
  `n/a` instead of guessing.

## Install

Requires Python >= 3.9 (CI matrix: 3.9 + 3.12, see `.github/workflows/ci.yml`).

```bash
cd <your-checkout-of-this-repo>
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

This installs the `binowl` console command.

## Usage

### 1. CLI: one-shot triage (auto ELF/PE detection)

```bash
binowl /bin/ls
binowl path/to/some.exe
```

Prints checksec status (NX / RELRO / PIE / W+X segments), entry point,
section table and program headers. Use `--format elf|pe` to force a format;
default is magic-byte auto-detection. Exit codes: `0` success, `2` file-level
error, `3` parse-level error.

### 2. CLI: packer & compiler fingerprint

```bash
binowl fp path/to/target.exe
```

Detects UPX (section layout + `UPX!` magic), MSVC Rich header
(doubly-anchored `DanS^key ↔ Rich^key`), stripped symbols and five
anti-debug API families, with the evidence spelled out:

```
fingerprint: UPX
  compiler: MSVC(modern, b30729)
  stripped: unknown
  evidence: 节名 UPX0+UPX1
  evidence: UPX! magic
  evidence: Rich 头 11 对 → msvc_modern（DOS stub 幸存）
  evidence: compiler: MSVC(modern, b30729)
  anti-debug: n/a（壳内/PE 判据不可用，诚实降级）
```

### 3. CLI: memory map & address translation

```bash
binowl map path/to/target --to-offset 0x10b0 --to-offset 0x100000
```

Prints the static memory map — ELF: every `PT_LOAD` with its file-backed
range, zero-fill tail (`.bss`) and page range; PE: header region and every
section (`VA = ImageBase + RVA`, default non-ASLR layout). `--to-offset`
translates virtual addresses to file offsets; zero-filled or unmapped
addresses report `<no file backing>` instead of a made-up offset:

```
LOAD #5  RW   vaddr [0x3d88, 0x4068) memsz 0x2e0
            file [0x2d88, 0x3060)  offset = 0x2d88 + (va - 0x3d88)
            zero-fill [0x4060, 0x4068)  pages [0x3000, 0x5000)
to-offset: va 0x10b0 -> file 0x10b0 (LOAD #3)
to-offset: va 0x100000 -> <no file backing> (zero-fill / unmapped)
```

### 4. MCP server (stdio)

```bash
binowl mcp
```

Speaks JSON-RPC over stdio (echoes MCP protocol version `2025-06-18`),
exposing the tools `info` (one-shot triage) and `map` (segment/section map).
Point any MCP client at it, e.g. for Claude Desktop:

```json
{
  "mcpServers": {
    "binowl": {"command": "binowl", "args": ["mcp"]}
  }
}
```

### Python module

```python
>>> import binowl
>>> binowl.__version__
'0.2.0'
>>> from binowl import elf, pe, fingerprint, map
```

## Sample output

`binowl tests/fixtures/bin_ls.elf` (ELF64 PIE):

```
Checksec: NX enabled (GNU_STACK RW) | RELRO full | PIE yes | W+X segs none
Entry: 0x6760  Sections: 30  Phdrs: 14
Nr  Name                     Type           Address                   Off       Size
[ 0]                          NULL           0x0000000000000000 0x00000000 0x00000000
[ 1] .note.gnu.property       NOTE           0x0000000000000350 0x00000350 0x00000020
[ 2] .note.gnu.build-id       NOTE           0x0000000000000370 0x00000370 0x00000024
...
```

## Use with AI agents (MCP)

binowl ships an MCP stdio server exposing two tools: `binowl_info` (triage
summary) and `binowl_map` (segment/section views). Every tool payload carries a
**`limitations`** field — a structured list of what the result does *not* claim
(stripped binaries, packed samples, byte-level-only observations), so agents
can reason about confidence, not just parse output.

**Claude Code:**

```bash
claude mcp add binowl -- python -m binowl.cli mcp
```

**Cursor / Codex / any MCP client (`mcp.json`):**

```json
{
  "mcpServers": {
    "binowl": { "command": "python", "args": ["-m", "binowl.cli", "mcp"] }
  }
}
```

Then ask your agent e.g. *"run binowl_info on this binary and tell me what the
limitations field says before you conclude anything."*

## Tests & fixtures

```bash
pip install pytest
pytest            # 181 assertions green locally (17 fixtures); on a fresh
                  # clone: 164 passed + 14 skipped — see provenance note below
```

Most fixtures are **regenerable** (self-constructed samples, no vendored
binaries):

```bash
python3 tests/build_samples.py    # 6 crafted ELF samples + m2_manifest.json
python3 tests/make_minidll.py     # minimal PE32+ DLL with export table
python3 tests/make_minipe.py      # minimal PE32+ EXE (with .idata)
python3 tests/make_fakerich.py    # fake-Rich negative sample (anti-trap)
```

**Provenance note (redistribution boundary, CHARTER §4):** the ELF anchor sample is
`dyn_ls` — **self-built** (tests/src/dyn_ls.c: distro-style dynamic PIE, Full RELRO,
strip, no .comment; regenerable, readelf 2.44/2.38 dual-snapshot verified). Three
fixtures are *not* shipped: `bin_ls.elf` (host `/bin/ls` — replaced by `dyn_ls`)
and `cli-64.exe` / `cli64_upx.exe` (setuptools-wheel bundled launcher + UPX
derivative, provenance registered in the manifest, replacement queued). On a
fresh clone the affected tests **skip automatically** with an explicit reason
(no silent degradation). Either way, the wheel itself ships **only** the
`binowl` package, never any fixture (`[tool.setuptools] packages = ["binowl"]`).

## Cross-validation against authoritative tools

Parser outputs are diffed against `readelf` / `objdump` / `pefile` — the
verification scripts live in `tests/` and double as usage examples:

```bash
python3 tests/verify_fingerprint.py    # fp: all fixtures vs readelf/pefile
python3 tests/verify_packaging.py      # wheel vs source-tree parity
```

## License

MIT — see [LICENSE](LICENSE).
