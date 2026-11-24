# 🦉 OCVSS

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Core%20/%20Utilities-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OCVSS** — CVSS 3.1/4.0 Calculator ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OCVSS — CVSS 3.1/4.0 Calculator. This tool is a professional, self-contained Go program. It provides an interactive cyan terminal UI and a full command-line interface with multi-format export (TXT, Markdown, JSON, CSV, SARIF 2.1.0), MITRE ATT&CK tagging on findings where meaningful, and A+..F posture grading.

---

## ✨ Features

- Score CVSS 3.1 and CVSS 4.0 vectors with interactive cyan TUI or CLI
- Explain individual metrics and compare multiple vectors side-by-side
- Normalize and validate vector strings; dictionary and guidance helpers
- Sensitivity analysis and SLA bucket mapping for prioritization
- MITRE ATT&CK tagging where meaningful and A+..F posture grading
- Export to TXT, Markdown, JSON, CSV or SARIF 2.1.0

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OCVSS OCVSS.go
./OCVSS --help
./OCVSS --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
./OCVSS --input vectors.txt --format sarif --output cvss.sarif
./OCVSS --compare --explain
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
