# HDD Firmware Hacking Toolkit Specification

## Purpose
A comprehensive tool for dumping, analyzing, patching, and hot-deploying HDD/SSD firmware via ATA passthrough and JTAG (OpenOCD). Covers workflows for Western Digital drives (based on Ryan Miceli's "HDD Firmware Hacking" blog series) and Samsung 840 EVO drives (based on Philipp Maier's "The Missing Manual").

## Features
- Firmware image parsing (WD LZHUF, Samsung PM871a nibble-swap)
- ATA passthrough / WD Vendor Specific Commands (VSC via SMART LOG 0xBE)
- Hot-patch deployer: Thumb-2 trampoline + code cave -- live RAM -- verify
- Overlay module enumeration and extraction
- OpenOCD JTAG bridge for breakpoints, memory dumps, register inspection
- Samsung MEX (840 EVO) workflow:
  - Full MEX memory map: ATCM/BTCM, GPIO, DMA, AES, flash channels, UART
  - SAFE mode activation (GPIO bit 17), UART protocol (rr/rw/~)
  - NCQ tracking + DMA descriptors + AES keychain extraction
  - Flash-aware reading with MEX channel interleaving
- USB bridge workflow:
  - SCSI-ATA Translation (SAT) for JMicron, ASMedia, Initio, Cypress, Sunplus
  - Chip-specific quirks: VSC passphrases (JMS578), XRAM injection (ASM2362)
  - ASM2362 NVMe bridge: XRAM dump, firmware injection, sanitize
- Data recovery:
  - Pattern-based read retry for SATA drives
  - HPA/DCO detection and access
- NVMe:
  - SanDisk/WD NVMe VSC: get-log-page, vendor-unique admin, sniff parsing
  - Live ioctl passthrough via NVME_IOCTL_ADMIN_CMD
  - Timing side-channel analysis
  - eNVMe / NVMe-over-Fabrics simulation
- Exploit development:
  - FirmwareUpdateExploit: send fw img, activate
  - ServiceArea: probe, dump, extract, hide
  - HotPatch: delay hook, code cave, benchmark
  - ASM2362 bridge attack: xram dump, firmware inject, sanitize

## Modules
- `core`: Models, enums, utilities (zero project imports)
- `ata`: ATA commands, SAT layer, WD VSC
- `firmware`: Firmware parsers (WD, Samsung, Toshiba, Seagate), patcher, detection
- `nvme`: NVMe admin passthrough, SanDisk VSC, timing side-channel, eNVMe, NVMe-over-Fabrics
- `hw`: JTAG (OpenOCD), USB bridge, data recovery, HPA/DCO
- `samsung_mex`: Samsung MEX memory map, GPIO, NCQ, safe UART, DMA, AES
- `exploit`: Firmware update exploits, hotpatching, service area manipulation, ASM2362 bridge attack
- `cli`: 85 command-line handlers covering all functionality
- `services`: Business logic layer coordinating between modules

## Requirements
- Python ≥3.11
- No external dependencies beyond Python standard library (uses ctypes for system calls)

## Usage
See `README.md` for installation and usage instructions.

## Testing
- 180 unit tests covering all modules
- Run with: `pytest tests/ -v`

## Linting
- Ruff enforces code style
- Run with: `ruff check src/`

## Versioning
- Single source of truth: `src/hdd_toolkit/_version.py`
- Follows semantic versioning

## Changelog
- See `CHANGELOG.md` for release notes

## License
- MIT License (see LICENSE file)