# Changelog

## [0.1.0] - 2026-05-15

### Added
- Initial release
- Firmware parsers (WD, Samsung, Seagate, Toshiba)
- ATA passthrough (Linux sg_io, Windows DeviceIoControl)
- WD VSC protocol read/write RAM, overlay dumps, hot-patches
- OpenOCD JTAG bridge with breakpoint, memory, register commands
- Samsung MEX (840 EVO) full support: GPIO, NCQ, AES, DMA, SAFE UART, flash channels
- NVMe admin passthrough (identify, SMART, FW download/activate)
- USB-SATA bridge detection database (JMicron, ASMedia, Initio, Cypress, etc.)
- FW patcher with apply, rollback, auto-checksum-fix
- Service Area operations (probe, dump, hide/extract data)
- Firmware update exploit (DOWNLOAD-MICROCODE offset overflow)
- ASM2362 NVMe bridge XRAM injection
- Patch templates (NOP sleds, data traps, exfil hooks, SMART redirect)
- Data recovery (retry escalation, bad sector handling)
- HPA/DCO detection and command building
- NVMe timing side-channel analysis
- eNVMe DMA attack modelling
- NVMe-oF TCP protocol and CVE-2023-5178 PoC
- Firmware detection via current draw, timing, checksums
- 32 CLI subcommands
- Comprehensive unit test suite (15 test files)
- SPEC.md documenting all public APIs
- pyproject.toml with ruff, pytest, mypy, coverage configs
- Pre-commit hooks, GitHub Actions CI, PyPI publish workflow
- AGENTS.md for agentic coding workflows
