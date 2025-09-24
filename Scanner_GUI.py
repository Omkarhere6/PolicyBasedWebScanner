"""
scanner_gui.py
Tkinter GUI wrapper for Web_Scanner.py
- Policy is loaded in backend (not shown in GUI)
- User inputs a full URL (including http:// or https://)
- Backend parses scheme/host/port and runs the scanner using allowed_ports + extra_ports
- Displays both Safe and Unsafe items in GUI
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
import urllib.parse

# Import scanner components (must be in same folder)
from Web_Scanner import Policy, ScannerEngine, Reporter, REPORTS_DIR, POC_DIR, pretty_json

POLICY_PATH = "policy.json"

class ScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Policy-Based Web Vulnerability Scanner (GUI)")
        self.root.geometry("900x550")

        # Load policy in backend
        try:
            self.policy = Policy.load(POLICY_PATH)
        except Exception:
            self.policy = Policy()

        # Top: URL entry + Run button
        top = tk.Frame(root)
        top.pack(fill="x", padx=12, pady=10)

        tk.Label(top, text="Enter full URL (include http:// or https://):").grid(row=0, column=0, sticky="w")
        self.entry_url = tk.Entry(top, width=70)
        self.entry_url.grid(row=0, column=1, padx=8, sticky="w")
        self.entry_url.insert(0, "https://demo.owasp-juice.shop")

        self.btn_scan = tk.Button(top, text="Run Scan", width=12, command=self.start_scan)
        self.btn_scan.grid(row=0, column=2, padx=6)

        # Middle: results text box with scrollbar
        mid = tk.Frame(root)
        mid.pack(expand=True, fill="both", padx=12, pady=(0,8))
        self.text_output = tk.Text(mid, wrap="word")
        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.text_output.yview)
        self.text_output.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.text_output.pack(side="left", expand=True, fill="both")

        # Bottom: Save report / open folder / reload policy
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=12, pady=(0,12))
        self.btn_save = tk.Button(bottom, text="Save Report", state="disabled", command=self.save_report)
        self.btn_save.pack(side="left")
        tk.Button(bottom, text="Open reports folder", command=self.open_reports_dir).pack(side="left", padx=8)
        tk.Button(bottom, text="Reload policy.json (backend)", command=self.reload_policy).pack(side="right")

        # ensure output directories exist
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(POC_DIR, exist_ok=True)

        # Internal storage
        self.findings = []
        self.last_scan_meta = {}

    def reload_policy(self):
        try:
            self.policy = Policy.load(POLICY_PATH)
            self._log(f"[i] Reloaded policy.json (backend). allowed_ports={self.policy.allowed_ports}, extra_ports={getattr(self.policy, 'extra_ports', [])}")
        except Exception as e:
            messagebox.showerror("Reload failed", f"Failed to reload policy.json: {e}")

    def start_scan(self):
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showerror("Input error", "Please enter a full URL including scheme (http:// or https://).")
            return

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            messagebox.showerror("Input error", "Please enter a valid URL including scheme and hostname.")
            return

        # Extract scheme, hostname, optional explicit port
        scheme = parsed.scheme
        host = parsed.hostname
        explicit_port = parsed.port

        # Determine ports to scan
        ports_set = set(self.policy.allowed_ports or [])
        ports_set.update(self.policy.extra_ports or [])
        if explicit_port:
            ports_set.add(int(explicit_port))

        ports = sorted(p for p in ports_set if isinstance(p, int))

        self.last_scan_meta = {"url": url, "scheme": scheme, "host": host, "ports": ports}

        self._log(f"[i] Parsed URL -> scheme={scheme}, host={host}, ports={ports} (policy-driven).")
        self._log(f"[i] Starting scan for {url} ...\n")

        self.btn_scan.config(state="disabled")
        self.btn_save.config(state="disabled")
        self.findings = []

        threading.Thread(target=self.run_scan, args=(host, scheme, ports), daemon=True).start()

    def run_scan(self, host, scheme, ports):
        try:
            engine = ScannerEngine(host, scheme, ports, self.policy)
            findings, safe_items = engine.run()
            self.findings = findings

            # Show safe items first
            self._log("\n✅ Safe items detected:")
            for category, items in safe_items.items():
                if items:
                    self._log(f"{category}:")
                    for it in items:
                        self._log(f"  - {it}")

            # Show findings
            if findings:
                self._log("\n⚠️ Findings:")
                for f in findings:
                    self._log(f"- [{f.severity}] {f.category}: {f.title}")
                    self._log(f"    Detection: {f.detection}")
                    self._log(f"    Remediation: {f.remediation}")
                    if f.evidence:
                        self._log("    Evidence: " + json.dumps(f.evidence, indent=2))
                    self._log("")
            else:
                self._log("\nNo policy violations detected.\n")

            self.btn_save.config(state="normal")
        except Exception as e:
            self._log(f"\n[!] Error while scanning: {e}\n")
        finally:
            self.btn_scan.config(state="normal")

    def save_report(self):
        try:
            host_label = self.last_scan_meta.get("host") or urllib.parse.quote_plus(self.last_scan_meta.get("url", "scan"))
            reporter = Reporter(REPORTS_DIR)
            json_path, md_path = reporter.write(host_label, self.findings)

            save_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON report", "*.json"), ("Markdown report", "*.md")],
                initialfile=os.path.basename(json_path)
            )
            if not save_path:
                return

            if save_path.lower().endswith(".md"):
                os.replace(md_path, save_path)
            else:
                os.replace(json_path, save_path)

            messagebox.showinfo("Saved", f"Report saved: {save_path}")
        except Exception as e:
            messagebox.showerror("Save failed", f"Failed to save report: {e}")

    def open_reports_dir(self):
        try:
            path = os.path.abspath(REPORTS_DIR)
            if os.name == "nt":
                os.startfile(path)
            elif os.uname().sysname == "Darwin":
                os.system(f"open {path}")
            else:
                os.system(f"xdg-open {path}")
        except Exception as e:
            messagebox.showerror("Open failed", f"Could not open reports folder: {e}")

    def _log(self, text):
        self.text_output.insert("end", text + ("\n" if not text.endswith("\n") else ""))
        self.text_output.see("end")


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerUI(root)
    root.mainloop()
