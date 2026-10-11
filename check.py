#!/usr/bin/env python3
import json
import glob
import sys


def load_latest_two():
    files = sorted(glob.glob("evidence_*.json"))
    if len(files) == 0:
        print("No evidence files found. Run collect.py first.")
        sys.exit(1)
    latest = json.load(open(files[-1]))
    previous = json.load(open(files[-2])) if len(files) >= 2 else None
    return latest, previous


def baseline_check(evidence):
    findings = []

    # AC-17 — Remote Access: PermitRootLogin should be no
    permit = evidence.get("ssh_config", {}).get("PermitRootLogin", "not set")
    if permit.lower() != "no":
        findings.append({
            "control": "AC-17",
            "check": "PermitRootLogin",
            "status": "FAIL",
            "detail": f"PermitRootLogin is '{permit}' — should be 'no'"
        })
    else:
        findings.append({
            "control": "AC-17",
            "check": "PermitRootLogin",
            "status": "PASS",
            "detail": "PermitRootLogin is set to no"
        })

    # AC-6 — Least Privilege: flag broad sudo access
    sudo_users = evidence.get("sudo_users", [])
    broad = [l for l in sudo_users if "ALL=(ALL:ALL) ALL" in l]
    if broad:
        findings.append({
            "control": "AC-6",
            "check": "Sudo access",
            "status": "WARN",
            "detail": f"{len(broad)} broad sudo entries found: {broad}"
        })
    else:
        findings.append({
            "control": "AC-6",
            "check": "Sudo access",
            "status": "PASS",
            "detail": "No broad sudo entries found"
        })

    # IA-2 — User accounts: flag unexpected UIDs
    users = evidence.get("users", [])
    if len(users) > 1:
        findings.append({
            "control": "IA-2",
            "check": "User accounts",
            "status": "WARN",
            "detail": f"{len(users)} interactive users found: {[u['name'] for u in users]}"
        })
    else:
        findings.append({
            "control": "IA-2",
            "check": "User accounts",
            "status": "PASS",
            "detail": f"Expected user count: {[u['name'] for u in users]}"
        })

    return findings


def drift_check(latest, previous):
    if previous is None:
        return ["No previous evidence file — drift check skipped"]

    drifts = []

    # Check for new or removed users
    old_users = {u["name"] for u in previous.get("users", [])}
    new_users = {u["name"] for u in latest.get("users", [])}
    added = new_users - old_users
    removed = old_users - new_users
    if added:
        drifts.append(f"NEW USER DETECTED: {added}")
    if removed:
        drifts.append(f"USER REMOVED: {removed}")

    # Check for sudo changes
    old_sudo = set(previous.get("sudo_users", []))
    new_sudo = set(latest.get("sudo_users", []))
    if old_sudo != new_sudo:
        drifts.append(f"SUDO CHANGE DETECTED — was: {old_sudo} | now: {new_sudo}")

    # Check for SSH config changes
    old_ssh = previous.get("ssh_config", {})
    new_ssh = latest.get("ssh_config", {})
    if old_ssh != new_ssh:
        drifts.append(f"SSH CONFIG CHANGE — was: {old_ssh} | now: {new_ssh}")

    if not drifts:
        drifts.append("No drift detected between runs")

    return drifts


def main():
    latest, previous = load_latest_two()

    print("\n=== BASELINE CHECK ===")
    findings = baseline_check(latest)
    for f in findings:
        print(f"[{f['status']}] {f['control']} — {f['check']}: {f['detail']}")

    print("\n=== DRIFT DETECTION ===")
    drifts = drift_check(latest, previous)
    for d in drifts:
        print(f"  {d}")

    print("\nDone.")


if __name__ == "__main__":
    main()
