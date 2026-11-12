"""Turn an Nmap service scan into a prioritized Markdown risk report.

Usage: python recon_report.py 192.168.56.101           (runs nmap -sV; only scan hosts you own)
       python recon_report.py --xml samples/scan.xml   (report from a saved scan)
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

DB = ("high", "Database reachable from the network", "Bind to localhost or firewall the port")
# Keyed by the service Nmap detected, not the port number, so telnet on port 2323 is still caught.
RISKY_SERVICES = {
    "telnet": ("high", "Cleartext remote login; passwords can be sniffed", "Disable telnet, use SSH"),
    "ftp": ("medium", "Cleartext file transfer", "Use SFTP or FTPS"),
    "microsoft-ds": ("high", "SMB exposed; common worm and ransomware entry point", "Block 445, allow only needed hosts"),
    "netbios-ssn": ("medium", "NetBIOS exposed; leaks host and share information", "Block 139 at the firewall"),
    "ms-wbt-server": ("high", "RDP exposed; frequent brute-force target", "Put behind a VPN, require NLA"),
    "vnc": ("high", "Remote desktop exposed, often weakly authenticated", "Tunnel over SSH or a VPN"),
    "mysql": DB, "postgresql": DB, "ms-sql-s": DB, "mongodb": DB, "redis": DB,
    "http": ("low", "Unencrypted web traffic", "Serve over HTTPS"),
}
# Service versions that shipped with a backdoor.
KNOWN_BAD = [
    (re.compile(r"vsftpd 2\.3\.4"), "CVE-2011-2523", "vsftpd 2.3.4 backdoor gives a root shell"),
    (re.compile(r"unrealircd 3\.2\.8\.1"), "CVE-2010-2075", "UnrealIRCd 3.2.8.1 backdoor allows remote commands"),
]
ORDER = ["critical", "high", "medium", "low"]


def parse(xml_text):
    """Nmap XML -> [{'addr': ip, 'ports': [{'port', 'proto', 'service', 'version'}]}], open ports only."""
    hosts = []
    for h in ET.fromstring(xml_text).iter("host"):
        ports = []
        for p in h.iter("port"):
            if p.find("state").get("state") != "open":
                continue
            s = p.find("service")
            s = s.attrib if s is not None else {}
            ports.append(dict(port=int(p.get("portid")), proto=p.get("protocol"),
                              service=s.get("name", "unknown"),
                              version=f"{s.get('product', '')} {s.get('version', '')}".strip()))
        hosts.append(dict(addr=h.find("address").get("addr"), ports=ports))
    return hosts


def assess(hosts):
    """Return findings sorted most severe first."""
    found = []
    for h in hosts:
        for p in h["ports"]:
            where = dict(host=h["addr"], port=p["port"], service=p["service"])
            for pattern, cve, why in KNOWN_BAD:
                if pattern.search(p["version"].lower()):
                    found.append(dict(where, severity="critical", issue=f"{why} ({cve})", fix="Upgrade or remove now"))
            if p["service"] in RISKY_SERVICES:
                sev, why, fix = RISKY_SERVICES[p["service"]]
                found.append(dict(where, severity=sev, issue=why, fix=fix))
    return sorted(found, key=lambda f: ORDER.index(f["severity"]))


def render(hosts, findings):
    counts = ", ".join(f"{sum(f['severity'] == s for f in findings)} {s}" for s in ORDER)
    out = ["# Recon report", "",
           f"{len(hosts)} hosts, {sum(len(h['ports']) for h in hosts)} open ports, {len(findings)} findings ({counts})",
           "", "## Findings", "",
           "| Severity | Host | Port | Service | Issue | Fix |", "|---|---|---|---|---|---|"]
    out += [f"| {f['severity'].upper()} | {f['host']} | {f['port']} | {f['service']} | {f['issue']} | {f['fix']} |"
            for f in findings]
    for h in hosts:
        out += ["", f"## {h['addr']} - open ports", "", "| Port | Service | Version |", "|---|---|---|"]
        out += [f"| {p['port']}/{p['proto']} | {p['service']} | {p['version'] or '-'} |" for p in h["ports"]]
    return "\n".join(out) + "\n"


def valid_target(target):
    """Allow only IPs, hostnames and CIDR ranges, so a 'target' can never be read by nmap as an option."""
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:/-]*", target) is not None


def scan(target):
    if not valid_target(target):
        sys.exit(f"invalid target: {target!r}")
    nmap = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"
    if not os.path.exists(nmap):
        sys.exit("nmap not found; install it from https://nmap.org or use --xml")
    # list form, no shell: the target is passed as one argument and never interpreted
    return subprocess.run([nmap, "-sV", "-T4", "-oX", "-", target],
                          capture_output=True, text=True, check=True).stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", nargs="?", help="IP, hostname or CIDR range you are authorized to scan")
    ap.add_argument("--xml", help="use a saved 'nmap -sV -oX' file instead of scanning")
    ap.add_argument("-o", "--out", help="write the Markdown report to this file")
    args = ap.parse_args()
    if bool(args.target) == bool(args.xml):
        ap.error("give either a target or --xml")

    if args.xml:
        with open(args.xml, encoding="utf-8") as f:
            xml_text = f.read()
    else:
        xml_text = scan(args.target)
    hosts = parse(xml_text)
    report = render(hosts, assess(hosts))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
    else:
        print(report)


if __name__ == "__main__":
    main()
