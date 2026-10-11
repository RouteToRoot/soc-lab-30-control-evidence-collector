# Lab 30 — Control Evidence Collector

## Overview
A Python-based security automation tool that collects system evidence, checks it against NIST 800-53 controls, and detects configuration drift between runs.

Built as part of the RouteToRoot cybersecurity lab portfolio.

## Scripts
- `collect.py` — Collects system evidence (user accounts, SSH config, sudo rights) and saves timestamped JSON output
- `check.py` — Checks latest evidence against a NIST 800-53 baseline and compares two runs for drift detection

## NIST 800-53 Controls Mapped
| Control | Description | Check |
|---|---|---|
| AC-17 | Remote Access | PermitRootLogin must be set to no |
| AC-6 | Least Privilege | Flags broad sudo access |
| IA-2 | User Accounts | Flags unexpected interactive users |

## Usage
```bash
# Collect evidence
sudo python3 collect.py

# Run baseline check and drift detection
sudo python3 check.py
```

## Environment
- Kali Linux 2025 (VMware Workstation)
- Python 3.11.9

## Notes
This is an early-stage learning project built to develop Python scripting skills for security automation. AI assistance was used in development. All code runs and was tested end-to-end on a live Kali Linux system.
