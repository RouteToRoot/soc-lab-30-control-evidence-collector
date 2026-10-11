#!/usr/bin/env python3
import json
import socket
from datetime import datetime


def get_users():
    users = []
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            name, uid, shell = parts[0], int(parts[2]), parts[6]
            if uid >= 1000 and not shell.endswith(("nologin", "false")):
                users.append({"name": name, "uid": uid, "shell": shell})
    return users


def get_ssh_config():
    settings = {}
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if line.startswith("PermitRootLogin"):
                    parts = line.split()
                    if len(parts) >= 2:
                        settings["PermitRootLogin"] = parts[1]
    except FileNotFoundError:
        settings["error"] = "sshd_config not found"
    return settings


def get_sudo_users():
    sudo_lines = []
    try:
        with open("/etc/sudoers") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "ALL" in line:
                    sudo_lines.append(line)
    except PermissionError:
        sudo_lines.append("Permission denied — run with sudo to read sudoers")
    return sudo_lines


def main():
    now = datetime.now()
    evidence = {
        "collected_at": now.isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "users": get_users(),
        "ssh_config": get_ssh_config(),
        "sudo_users": get_sudo_users(),
    }
    out = "evidence_" + now.strftime("%Y%m%d_%H%M%S") + ".json"
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print("Saved", out)


if __name__ == "__main__":
    main()
