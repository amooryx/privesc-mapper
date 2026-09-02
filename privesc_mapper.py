#!/usr/bin/env python3
"""
Privesc Mapper — Linux Privilege Escalation Enumeration Tool
Checks for SUID/SGID binaries, writable paths in $PATH, sudo misconfigs, cron wildcards, and more.
Author: Omar Khalid (amooryx) | github.com/amooryx/privesc-mapper
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import os
import platform
import pwd
import stat
import subprocess
import sys
from pathlib import Path

def run(cmd: str) -> str:
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""

def check_suid_sgid() -> list[dict]:
    findings = []
    suid_bins = run("find / -perm -4000 -type f 2>/dev/null").splitlines()
    sgid_bins = run("find / -perm -2000 -type f 2>/dev/null").splitlines()
    # GTFOBins-listed dangerous SUID binaries
    dangerous = {"bash", "sh", "python", "python3", "perl", "ruby", "find",
                 "vim", "vi", "nano", "less", "more", "awk", "nmap", "nc", "netcat",
                 "cp", "mv", "dd", "tee", "tar", "zip", "unzip", "curl", "wget",
                 "git", "env", "strace", "man", "sudo", "pkexec"}
    for path in suid_bins + sgid_bins:
        name = Path(path).name.split(".")[0]
        if name.lower() in dangerous:
            findings.append({
                "type": "suid_sgid",
                "path": path,
                "binary": name,
                "note": f"SUID/SGID on GTFOBins-listed binary: {name}",
                "severity": "High",
            })
    return findings

def check_sudo() -> list[dict]:
    findings = []
    sudo_l = run("sudo -l 2>/dev/null")
    if sudo_l:
        findings.append({"type": "sudo_config", "output": sudo_l})
        if "(ALL" in sudo_l and "NOPASSWD" in sudo_l:
            findings.append({
                "type": "sudo_nopasswd_all",
                "note": "NOPASSWD sudo for ALL commands — trivial root",
                "severity": "Critical",
            })
        for dangerous in ["/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/vim"]:
            if dangerous in sudo_l and "NOPASSWD" in sudo_l:
                findings.append({
                    "type": "sudo_nopasswd_gtfobin",
                    "binary": dangerous,
                    "note": f"NOPASSWD sudo for {dangerous} — GTFOBins escalation",
                    "severity": "Critical",
                })
    return findings

def check_writable_path() -> list[dict]:
    findings = []
    path_dirs = os.environ.get("PATH", "").split(":")
    for d in path_dirs:
        try:
            if os.access(d, os.W_OK):
                findings.append({
                    "type": "writable_path_dir",
                    "path": d,
                    "note": f"Writable directory in $PATH: {d} — can hijack any command",
                    "severity": "High",
                })
        except Exception:
            pass
    return findings

def check_cron() -> list[dict]:
    findings = []
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"]
    for d in cron_dirs:
        try:
            for f in Path(d).iterdir():
                content = f.read_text(errors="ignore")
                # Look for wildcard abuse and writable scripts
                if "*" in content and ("tar" in content or "chmod" in content or "chown" in content):
                    findings.append({
                        "type": "cron_wildcard",
                        "file": str(f),
                        "note": "Cron job uses wildcards with tar/chmod — possible wildcard injection",
                        "severity": "Medium",
                    })
                for line in content.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[0] != "#":
                        script = parts[5] if len(parts) > 5 else ""
                        if script and os.path.exists(script) and os.access(script, os.W_OK):
                            findings.append({
                                "type": "writable_cron_script",
                                "script": script,
                                "note": f"Writable cron script: {script}",
                                "severity": "High",
                            })
        except Exception:
            pass
    return findings

def check_world_writable() -> list[dict]:
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                 "/etc/crontab", "/etc/environment"]
    findings = []
    for path in sensitive:
        try:
            mode = os.stat(path).st_mode
            if mode & stat.S_IWOTH:
                findings.append({
                    "type": "world_writable_sensitive",
                    "path": path,
                    "note": f"World-writable sensitive file: {path}",
                    "severity": "Critical",
                })
        except Exception:
            pass
    return findings

def system_info() -> dict:
    return {
        "hostname": run("hostname"),
        "uname":    run("uname -a"),
        "whoami":   run("whoami"),
        "id":       run("id"),
        "os":       run("cat /etc/os-release | head -5"),
        "kernel":   run("uname -r"),
    }

def main():
    parser = argparse.ArgumentParser(
        description="Privesc Mapper — Linux Privilege Escalation Enum (Authorized use only)",
    )
    parser.add_argument("--suid",     action="store_true", help="Check SUID/SGID binaries")
    parser.add_argument("--sudo",     action="store_true", help="Check sudo configuration")
    parser.add_argument("--path",     action="store_true", help="Check writable PATH dirs")
    parser.add_argument("--cron",     action="store_true", help="Check cron jobs")
    parser.add_argument("--writable", action="store_true", help="Check world-writable sensitive files")
    parser.add_argument("--all", "-a", action="store_true")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    if platform.system() != "Linux":
        print("[!] Warning: This tool is designed for Linux systems")

    print("[*] System info:")
    info = system_info()
    for k, v in info.items():
        if v:
            print(f"    {k}: {v[:80]}")

    all_findings = []
    if not (args.suid or args.sudo or args.path or args.cron or args.writable or args.all):
        args.all = True

    if args.suid or args.all:
        print("\n[*] Checking SUID/SGID binaries ...")
        f = check_suid_sgid()
        all_findings.extend(f)
        for x in f:
            print(f"  [{x['severity']}] {x['path']}: {x['note']}")

    if args.sudo or args.all:
        print("\n[*] Checking sudo configuration ...")
        f = check_sudo()
        all_findings.extend(f)
        for x in f:
            if "severity" in x:
                print(f"  [{x['severity']}] {x['note']}")

    if args.path or args.all:
        print("\n[*] Checking writable PATH directories ...")
        f = check_writable_path()
        all_findings.extend(f)
        for x in f:
            print(f"  [{x['severity']}] {x['path']}")

    if args.cron or args.all:
        print("\n[*] Checking cron jobs ...")
        f = check_cron()
        all_findings.extend(f)
        for x in f:
            print(f"  [{x.get('severity','?')}] {x.get('note','')}")

    if args.writable or args.all:
        print("\n[*] Checking world-writable sensitive files ...")
        f = check_world_writable()
        all_findings.extend(f)
        for x in f:
            print(f"  [{x['severity']}] {x['path']}")

    critical = [f for f in all_findings if f.get("severity") == "Critical"]
    high     = [f for f in all_findings if f.get("severity") == "High"]
    print(f"\n[*] Summary: {len(all_findings)} findings | Critical: {len(critical)} | High: {len(high)}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"system": info, "findings": all_findings}, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
