import unittest
from pathlib import Path

from recon_report import assess, parse, render, valid_target

SAMPLE = (Path(__file__).parent / "samples" / "scan.xml").read_text(encoding="utf-8")


def one_port(port, name, product="", version="", state="open"):
    return (f'<nmaprun><host><address addr="10.0.0.5"/><ports><port protocol="tcp" portid="{port}">'
            f'<state state="{state}"/><service name="{name}" product="{product}" version="{version}"/>'
            f'</port></ports></host></nmaprun>')


class Tests(unittest.TestCase):
    def test_parse_sample(self):
        hosts = parse(SAMPLE)
        self.assertEqual([h["addr"] for h in hosts], ["192.168.56.101", "192.168.56.102"])
        self.assertEqual(len(hosts[0]["ports"]), 10)  # 11 listed, 1 closed

    def test_closed_ports_ignored(self):
        self.assertEqual(assess(parse(one_port(23, "telnet", state="closed"))), [])

    def test_backdoored_version_is_critical_and_first(self):
        findings = assess(parse(SAMPLE))
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(sum(f["severity"] == "critical" for f in findings), 2)
        self.assertIn("CVE-2011-2523", " ".join(f["issue"] for f in findings))

    def test_patched_version_not_flagged_as_backdoor(self):
        sev = [f["severity"] for f in assess(parse(one_port(21, "ftp", "vsftpd", "3.0.5")))]
        self.assertEqual(sev, ["medium"])

    def test_service_on_unusual_port(self):
        findings = assess(parse(one_port(2323, "telnet")))
        self.assertEqual([(f["port"], f["severity"]) for f in findings], [(2323, "high")])

    def test_hardened_host_has_no_findings(self):
        self.assertNotIn("192.168.56.102", {f["host"] for f in assess(parse(SAMPLE))})

    def test_port_without_service_element(self):
        xml = ('<nmaprun><host><address addr="10.0.0.5"/><ports><port protocol="tcp" portid="9">'
               '<state state="open"/></port></ports></host></nmaprun>')
        self.assertEqual(parse(xml)[0]["ports"][0]["service"], "unknown")

    def test_render(self):
        hosts = parse(SAMPLE)
        report = render(hosts, assess(hosts))
        self.assertIn("2 hosts, 12 open ports, 10 findings (2 critical, 5 high, 2 medium, 1 low)", report)
        self.assertIn("| CRITICAL | 192.168.56.101 | 21 | ftp |", report)

    def test_target_validation(self):
        for good in ["192.168.56.101", "192.168.56.0/24", "scanme.nmap.org", "fe80::1"]:
            self.assertTrue(valid_target(good), good)
        for bad in ["-oN/tmp/x", "--script=evil", "10.0.0.1; rm -rf /", "a b", ""]:
            self.assertFalse(valid_target(bad), bad)


if __name__ == "__main__":
    unittest.main()
