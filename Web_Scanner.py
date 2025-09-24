#!/usr/bin/env python3
"""
Policy-Based Web Vulnerability Detection & Exploitation Framework
-----------------------------------------------------------------
Single-file Python implementation that:
  • Loads a security policy (JSON/YAML*) describing allowed ports, TLS versions, and required headers
  • Scans a target website/host using four modules: Port, TLS, Certificate, and Header scanners
  • Performs safe "exploitation" (validation PoCs) for each finding
  • Generates console output + JSON and Markdown reports (in ./reports)

* YAML requires PyYAML; if unavailable, provide JSON policy. See sample policy below.

USAGE EXAMPLES
--------------
python policy_web_scanner.py --host example.com \
  --ports 80,443,21,22 --scheme https --policy policy.json

python policy_web_scanner.py --host 127.0.0.1 --ports 80,443 --scheme http

SAMPLE POLICY (JSON)
--------------------
{
  "allowed_ports": [80, 443],
  "required_headers": {
    "Strict-Transport-Security": "^max-age=\\d+",
    "Content-Security-Policy": ".+",
    "X-Frame-Options": "^(DENY|SAMEORIGIN)$",
    "X-Content-Type-Options": "^nosniff$",
    "Referrer-Policy": ".+"
  },
  "allowed_tls_versions": ["TLSv1.2", "TLSv1.3"],
  "min_cert_days_valid": 30
}

DISCLAIMER
----------
This tool is intended for educational use in *authorized* environments. Do not scan
or test systems you do not own or lack written permission to assess.
"""

import argparse
import datetime as dt
import json
import os
import re
import socket
import ssl
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
except Exception:
    urllib_request = None  # Fallback handled later

# Optional YAML support
try:
    import yaml  # type: ignore
    HAS_YAML = True
except Exception:
    HAS_YAML = False

REPORTS_DIR = os.path.join(os.getcwd(), "reports")
POC_DIR = os.path.join(os.getcwd(), "poc_output")

# ----------------------------- Utilities -----------------------------

def mkdir_p(path: str):
    os.makedirs(path, exist_ok=True)


def pretty_json(data) -> str:
    return json.dumps(data, indent=2, sort_keys=False, default=str)


# ----------------------------- Policy -----------------------------
@dataclass
class Policy:
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443])
    required_headers: Dict[str, str] = field(default_factory=dict)
    allowed_tls_versions: List[str] = field(default_factory=lambda: ["TLSv1.2", "TLSv1.3"])
    min_cert_days_valid: int = 30
    extra_ports: List[int] = field(default_factory=list) 

    @staticmethod
    def load(path: Optional[str]) -> "Policy":
        if not path:
            return Policy()
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        data = None
        if path.lower().endswith((".yaml", ".yml")) and HAS_YAML:
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)
        return Policy(
            allowed_ports=[int(p) for p in data.get("allowed_ports", [80, 443])],
            required_headers=data.get("required_headers", {}),
            allowed_tls_versions=data.get("allowed_tls_versions", ["TLSv1.2", "TLSv1.3"]),
            min_cert_days_valid=int(data.get("min_cert_days_valid", 30)),
            extra_ports=[int(p) for p in data.get("extra_ports", [])]
        )


# ----------------------------- Results Model -----------------------------
@dataclass
class Finding:
    category: str
    title: str
    severity: str
    detection: str
    exploitation: str
    remediation: str
    evidence: Dict[str, str] = field(default_factory=dict)


# ----------------------------- Port Scanner -----------------------------
class PortScanner:
    def __init__(self, host: str, ports: List[int], timeout: float = 2.0):
        self.host = host
        self.ports = ports
        self.timeout = timeout

    def scan(self) -> List[Tuple[int, str, Optional[str]]]:
        results = []
        for port in self.ports:
            status, banner = self._scan_port(port)
            results.append((port, status, banner))
        return results

    def _scan_port(self, port: int) -> Tuple[str, Optional[str]]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, port))
            status = "open"
            # Safe exploitation: banner grab (limited bytes)
            banner = None
            try:
                s.settimeout(1.0)
                banner = s.recv(128).decode(errors="ignore")
                banner = banner.strip() if banner else None
            except Exception:
                banner = None
        except (socket.timeout, ConnectionRefusedError):
            status = "closed"
            banner = None
        except OSError:
            status = "filtered"
            banner = None
        finally:
            try:
                s.close()
            except Exception:
                pass
        return status, banner


# ----------------------------- TLS & Certificate Scanner -----------------------------
TLS_NAME_TO_VERSION = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

class TLSScanner:
    def __init__(self, host: str, port: int = 443, server_hostname: Optional[str] = None, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.server_hostname = server_hostname or host
        self.timeout = timeout

    def try_version(self, version_name: str) -> Tuple[bool, str]:
        version = TLS_NAME_TO_VERSION.get(version_name)
        if version is None:
            return False, f"Unsupported version name: {version_name}"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we only test protocol support
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.server_hostname) as ssock:
                    cipher = ssock.cipher()
                    return True, f"Handshake OK with {version_name}; cipher={cipher}"
        except Exception as e:
            return False, f"Handshake failed for {version_name}: {e}"

    def fetch_certificate(self) -> Tuple[Optional[dict], Optional[str]]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.server_hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert, None
        except Exception as e:
            return None, str(e)


# ----------------------------- Header Scanner -----------------------------
class HeaderScanner:
    def __init__(self, url: str, timeout: float = 5.0):
        self.url = url
        self.timeout = timeout

    def fetch_headers(self) -> Tuple[Dict[str, str], Optional[str]]:
        if urllib_request is None:
            return {}, "urllib is unavailable in this environment"
        req = urllib_request.Request(self.url, method="GET")
        req.add_header("User-Agent", "PolicyScanner/1.0")
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k: v for k, v in resp.headers.items()}
                return headers, None
        except urllib_error.HTTPError as e:
            return dict(e.headers.items()) if e.headers else {}, f"HTTP error: {e.code}"
        except Exception as e:
            return {}, str(e)


# ----------------------------- Report Writer -----------------------------
class Reporter:
    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        mkdir_p(self.out_dir)

    def write(self, host: str, findings: List[Finding]):
        ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base = os.path.join(self.out_dir, f"report_{host}_{ts}")
        data = [f.__dict__ for f in findings]
        # JSON
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        # Markdown (easy to paste into docs)
        md = [f"# Security Scan Report for {host}", f"_UTC: {ts}_", ""]
        for fnd in findings:
            md.append(f"## [{fnd.severity}] {fnd.category}: {fnd.title}")
            md.append("**Detection**:\n" + fnd.detection)
            md.append("**Exploitation (PoC)**:\n" + fnd.exploitation)
            md.append("**Remediation**:\n" + fnd.remediation)
            if fnd.evidence:
                md.append("**Evidence**\n`````\n" + pretty_json(fnd.evidence) + "\n`````")
            md.append("")
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write("\n".join(md))
        return base + ".json", base + ".md"


# ----------------------------- PoC Generators -----------------------------

def save_clickjacking_poc(target_url: str, out_dir: str) -> str:
    mkdir_p(out_dir)
    html = f"""
<!doctype html>
<html>
<head><meta charset=\"utf-8\"><title>Clickjacking PoC</title></head>
<body>
<h2>Clickjacking PoC for {target_url}</h2>
<iframe src=\"{target_url}\" width=\"1000\" height=\"700\"></iframe>
<p>If the page loads above, lack of X-Frame-Options/Content-Security-Policy allows framing.</p>
</body>
</html>
""".strip()
    path = os.path.join(out_dir, "clickjacking_poc.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ----------------------------- Engine -----------------------------
class ScannerEngine:
    def __init__(self, host: str, scheme: str, ports: List[int], policy: Policy):
        self.host = host
        self.scheme = scheme
        self.ports = ports
        self.policy = policy
        mkdir_p(REPORTS_DIR)
        mkdir_p(POC_DIR)

    def run(self) -> tuple:
        findings: List[Finding] = []
        safe: Dict[str, list] = {"Ports": [], "TLS": [], "Certificates": [], "Headers": []}

        # -------- Ports --------
        port_scanner = PortScanner(self.host, self.ports)
        port_results = port_scanner.scan()
        for port, status, banner in port_results:
            if status == "open":
                if port in self.policy.allowed_ports:
                    safe["Ports"].append(f"{port} (allowed, open)")
                else:
                    findings.append(Finding(
                        category="Port",
                        title=f"Unexpected open port {port}",
                        severity="Medium",
                        detection=f"Port {port} is open but not allowed by policy {self.policy.allowed_ports}",
                        exploitation=f"Banner: {banner or 'None'}",
                        remediation="Close/restrict port",
                        evidence={"port": port, "status": status, "banner": banner or ""}
                    ))

        # -------- TLS --------
        tls_port = 443 if 443 in self.ports or self.scheme == "https" else None
        if tls_port:
            tls = TLSScanner(self.host, tls_port)
            for version in ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
                ok, msg = tls.try_version(version)
                if ok:
                    if version in self.policy.allowed_tls_versions:
                        safe["TLS"].append(version)
                    else:
                        findings.append(Finding(
                            category="TLS",
                            title=f"Weak TLS protocol {version} accepted",
                            severity="Medium",
                            detection=f"Server supports {version}, allowed: {self.policy.allowed_tls_versions}",
                            exploitation=msg,
                            remediation="Disable legacy TLS",
                            evidence={"accepted_versions": version}
                        ))

        # -------- Certificate --------
        cert, err = tls.fetch_certificate() if tls_port else (None, "TLS not available")
        if cert:
            not_after = cert.get("notAfter")
            days_left = None
            if not_after:
                try:
                    exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                    days_left = (exp - dt.datetime.utcnow()).days
                except Exception:
                    pass
            if days_left is not None and days_left >= self.policy.min_cert_days_valid:
                safe["Certificates"].append(f"Valid certificate ({days_left} days left)")
            elif days_left is not None:
                findings.append(Finding(
                    category="Certificate",
                    title="Certificate near expiry",
                    severity="Medium" if days_left >= 0 else "High",
                    detection=f"Certificate expires in {days_left} day(s). Policy requires >= {self.policy.min_cert_days_valid}",
                    exploitation="Inspected certificate validity",
                    remediation="Renew certificate",
                    evidence={"notAfter": not_after}
                ))
        else:
            findings.append(Finding(
                category="Certificate",
                title="Certificate retrieval failed",
                severity="High",
                detection=f"Could not fetch certificate: {err}",
                exploitation="N/A",
                remediation="Fix TLS endpoint",
                evidence={"error": err or ""}
            ))

        # -------- Headers --------
        base_url = f"{self.scheme}://{self.host}"
        hdr_scanner = HeaderScanner(base_url)
        headers, hdr_err = hdr_scanner.fetch_headers()
        if headers and not hdr_err:
            for hname, pattern in self.policy.required_headers.items():
                val = headers.get(hname)
                if val and re.search(pattern, val):
                    safe["Headers"].append(f"{hname}: {val}")
                else:
                    findings.append(Finding(
                        category="Headers",
                        title=f"Missing/weak header: {hname}",
                        severity="Medium",
                        detection=f"Header '{hname}' value: {val} does not match policy regex: {pattern}",
                        exploitation="Generated PoC if applicable",
                        remediation=f"Add/strengthen '{hname}'",
                        evidence={"observed_value": val or "(absent)"}
                    ))

        return findings, safe


# ----------------------------- CLI -----------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Policy-Based Web Vulnerability Detection & Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python policy_web_scanner.py --host example.com --ports 80,443 --scheme https --policy policy.json
              python policy_web_scanner.py --host 10.0.0.5 --ports 80,443,21,22 --scheme http
            """
        )
    )
    p.add_argument("--host", required=True, help="Hostname or IP to scan")
    p.add_argument("--ports", default="80,443", help="Comma-separated list of TCP ports to check")
    p.add_argument("--scheme", choices=["http", "https"], default="https", help="Base scheme for header requests")
    p.add_argument("--policy", help="Path to policy file (JSON or YAML)")
    p.add_argument("--out", default=REPORTS_DIR, help="Reports output directory")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    except ValueError:
        print("[!] Invalid --ports list", file=sys.stderr)
        sys.exit(2)

    policy = Policy.load(args.policy)
    print("[i] Loaded policy:\n" + pretty_json(policy.__dict__))

    engine = ScannerEngine(args.host, args.scheme, ports, policy)
    findings = engine.run()

    # Console summary
    if not findings:
        print("\n✅ No policy violations detected.")
    else:
        print("\n⚠️  Findings:")
        for f in findings:
            print(f"- [{f.severity}] {f.category}: {f.title}")

    # Reports
    reporter = Reporter(args.out)
    jspath, mdpath = reporter.write(args.host, findings)
    print(f"\nReports written:\n  JSON: {jspath}\n  Markdown: {mdpath}")

    # PoC location reminder
    if os.path.isdir(POC_DIR) and os.listdir(POC_DIR):
        print(f"PoC artifacts (e.g., clickjacking HTML) saved in: {POC_DIR}")


if __name__ == "__main__":
    main()
