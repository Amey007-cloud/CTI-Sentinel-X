"""CTI Sentinel optional host posture scanner.

Read-only checks only. It does not install, upgrade, disable, delete or execute
remediation commands. Run locally on the host you intend to assess.
"""
from __future__ import annotations
import argparse, json, os, platform, socket, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import requests

APP_URL = os.getenv("CTI_SENTINEL_URL", "http://127.0.0.1:5000").rstrip("/")


def command(args: list[str], timeout: int = 12) -> tuple[str, int]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return (p.stdout or p.stderr or "").strip(), p.returncode
    except Exception as exc:
        return str(exc), 1


def add(checks, title, status, detail, recommendation):
    checks.append({"id": title.lower().replace(" ", "_"), "title": title,
                   "status": status, "detail": detail[:1200],
                   "recommendation": recommendation})


def scan_windows(checks):
    info, _ = command(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress)"])
    try:
        data = json.loads(info) if info else {}
        os_version = f"{data.get('Caption','Windows')} · {data.get('Version','')} build {data.get('BuildNumber','')}"
    except Exception:
        os_version = platform.platform()
    defender, code = command(["powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress)"])
    try:
        d = json.loads(defender)
        okay = bool(d.get("AntivirusEnabled")) and bool(d.get("RealTimeProtectionEnabled"))
        add(checks, "Microsoft Defender", "PASS" if okay else "WARN", str(d), "Verify Defender health and signatures in Windows Security or your managed EDR console.")
    except Exception:
        add(checks, "Microsoft Defender", "INFO", "Defender status could not be queried in this execution context.", "Confirm endpoint protection status with your authorized endpoint management console.")
    firewall, _ = command(["powershell", "-NoProfile", "-Command", "(Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress)"])
    try:
        fw = json.loads(firewall); fw = fw if isinstance(fw, list) else [fw]
        disabled = [x.get("Name") for x in fw if not x.get("Enabled")]
        add(checks, "Windows Firewall", "PASS" if fw and not disabled else "WARN", json.dumps(fw), "Review firewall profiles and enable required protections through managed policy.")
    except Exception:
        add(checks, "Windows Firewall", "INFO", "Firewall profile status could not be queried.", "Verify firewall state using Windows Security or endpoint management.")
    hotfix, _ = command(["powershell", "-NoProfile", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn | ConvertTo-Json -Compress)"])
    add(checks, "Latest installed hotfix", "INFO", hotfix or "No hotfix data returned.", "Compare installed updates with the exact Windows build and Microsoft Security Response Center advisories.")
    return os_version


def scan_linux(checks):
    os_version = platform.platform()
    try:
        data = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1); data[k] = v.strip('"')
        os_version = f"{data.get('PRETTY_NAME', os_version)} · kernel {platform.release()}"
    except Exception:
        pass
    ufw, code = command(["ufw", "status"])
    if code == 0:
        status = "PASS" if "Status: active" in ufw else "WARN"
        add(checks, "UFW firewall", status, ufw, "Review host firewall policy and exposed services with the system owner.")
    else:
        fw, fwcode = command(["systemctl", "is-active", "firewalld"])
        add(checks, "Host firewall", "PASS" if fw.strip() == "active" else "INFO", fw or "Could not query UFW/firewalld.", "Confirm nftables, firewalld, UFW or cloud security-group controls appropriate to this host.")
    add(checks, "Kernel identification", "INFO", platform.release(), "Compare the kernel package with your distribution's security tracker; distributions may backport fixes.")
    ssh, _ = command(["systemctl", "is-active", "ssh"])
    if not ssh:
        ssh, _ = command(["systemctl", "is-active", "sshd"])
    add(checks, "SSH service", "INFO", ssh or "Service state unavailable.", "If SSH is enabled, restrict source networks and review key-based authentication and privileged access.")
    return os_version


def scan_macos(checks):
    version, _ = command(["sw_vers"])
    os_version = version.replace("\n", " · ") or platform.platform()
    filevault, code = command(["fdesetup", "status"])
    add(checks, "FileVault encryption", "PASS" if code == 0 and "FileVault is On" in filevault else "WARN" if code == 0 else "INFO", filevault, "Verify encryption policy and recovery-key escrow through your approved MDM workflow.")
    updates, code = command(["softwareupdate", "-l"], timeout=25)
    add(checks, "Software update inventory", "INFO" if code == 0 else "WARN", updates[:1000] or "No update details returned.", "Review available updates against Apple's security releases and your change window.")
    firewall, code = command(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    add(checks, "Application firewall", "PASS" if "enabled" in firewall.lower() else "WARN" if code == 0 else "INFO", firewall, "Review macOS firewall configuration with the device owner or MDM policy.")
    return os_version


def run_once() -> int:
    checks = []
    system = platform.system().upper()
    if system == "WINDOWS":
        platform_name = "WINDOWS"; os_version = scan_windows(checks)
    elif system == "LINUX":
        platform_name = "LINUX"; os_version = scan_linux(checks)
    elif system == "DARWIN":
        platform_name = "MACOS"; os_version = scan_macos(checks)
    else:
        print(f"Unsupported host OS: {system}. Supported: Windows, Linux, macOS."); return 2
    payload = {"scan_id": str(uuid.uuid4()), "hostname": socket.gethostname(), "platform": platform_name,
               "os_version": os_version, "scanner_version": "1.1.0", "checks": checks,
               "scanned_at": datetime.now(timezone.utc).isoformat()}
    print(json.dumps(payload, indent=2))
    try:
        response = requests.post(f"{APP_URL}/api/assistant/host-scan", json=payload, timeout=20)
        response.raise_for_status()
        print(f"\\n[PASS] Posture scan saved to CTI Sentinel ({response.json().get('scan_id')}).")
    except Exception as exc:
        print(f"\\n[ERROR] Scan collected locally but could not be saved: {exc}")
        print(f"Set CTI_SENTINEL_URL if the app is not at {APP_URL}.")
        return 1
    print("[INFO] Read-only scanner: no settings changed and no remediation commands executed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="CTI Sentinel read-only local posture scanner.")
    parser.add_argument("--watch", action="store_true",
                        help="repeat read-only inventory checks until interrupted (Ctrl+C)")
    parser.add_argument("--interval", type=int, default=900,
                        help="watch interval in seconds (minimum 60; default 900)")
    args = parser.parse_args()
    if args.interval < 60:
        parser.error("--interval must be at least 60 seconds.")
    if not args.watch:
        return run_once()
    print(f"[WATCH] Read-only posture monitoring every {args.interval} seconds. Press Ctrl+C to stop.")
    try:
        while True:
            run_once()
            print(f"[WATCH] Next snapshot in {args.interval} seconds.")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\\n[STOP] Posture watcher stopped cleanly.")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
