# AGENTS.md — HDD Firmware Toolkit

## Project Structure

```
hdd-toolkit/
├── src/hdd_toolkit/
│   ├── __init__.py          # Top-level imports from all sub-modules
│   ├── __main__.py          # python -m entry point
│   ├── _version.py          # __version__ = "0.1.0"
│   ├── py.typed
│   ├── ata/                 # ATA commands, SAT, WD VSC
│   ├── cli/                 # build_parser() and main(), 85 CLI handlers
│   ├── core/                # Models, enums, utils — zero project imports
│   ├── exploit/             # Fw update, hotpatch, service area, bridge attack
│   ├── firmware/            # WD, Samsung, Toshiba, Seagate parsers + patcher
│   ├── hw/                  # JTAG, USB bridge, data recovery, HPA/DCO
│   ├── nvme/                # Admin, SanDisk VSC, timing, eNVMe, Fabrics
│   └── samsung_mex/         # MEX memory map, GPIO, NCQ, UART, DMA, AES
├── tests/                   # 16 test files, 180 tests
├── pyproject.toml           # hatchling, ruff, pytest, mypy
└── SPEC.md                  # Complete public API documentation
```

## Architecture

- `core/` → no project imports
- `adapters/` → imports from `core/`
- `services/` → imports from `core/` and `adapters/`
- `cli/` → imports from anything
- `data/` → standalone reference data

All concrete implementations live in sub-modules organized by domain
(`ata/`, `firmware/`, `nvme/`, `hw/`, `exploit/`, `samsung_mex/`).
Tests import directly from sub-modules (never from `_monolith` — it no longer exists).

## Build & Test Commands

- `pytest tests/ -v` — run tests
- `ruff check src/` — lint
- `ruff format src/` — format
- `mypy src/` — type check (`--ignore-missing-imports`)
- `python -m build` — build distribution
- `bump2version patch` — bump version

## Conventions

- Python >= 3.11
- No emoji in code or docs
- Pure ASCII docstrings only
- Test files: `tests/test_<subsystem>_<module>.py`
- Avoid adding comments to code
- Every new class needs docstring with `Sources:` section
- Cross-reference new techniques against INVESTIGATION.md

## Version

Current: 0.1.0
