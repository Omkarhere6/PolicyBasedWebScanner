# policy_web_scanner_tk.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os

# Import your existing scanner classes
from Web_Scanner import Policy, ScannerEngine, Reporter, REPORTS_DIR, POC_DIR

import re

def sanitize_host_display(host: str) -> str:
    """Remove scheme and replace invalid characters for filenames/display."""
    # Remove http:// or https://
    host = re.sub(r'^https?://', '', host)
    # Optionally replace non-alphanumeric chars with _
    host = re.sub(r'[^A-Za-z0-9._-]', '_', host)
    return host


# ----------------- GUI Setup -----------------
class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Policy Web Scanner")
        root.geometry("800x600")

        # Inputs
        frame_inputs = tk.Frame(root)
        frame_inputs.pack(fill="x", padx=10, pady=5)

        tk.Label(frame_inputs, text="Host:").grid(row=0, column=0, sticky="w")
        self.entry_host = tk.Entry(frame_inputs, width=30)
        self.entry_host.grid(row=0, column=1, sticky="w")

        tk.Label(frame_inputs, text="Scheme:").grid(row=0, column=2, sticky="w", padx=(10,0))
        self.scheme_var = tk.StringVar(value="https")
        tk.OptionMenu(frame_inputs, self.scheme_var, "http", "https").grid(row=0, column=3, sticky="w")

        tk.Label(frame_inputs, text="Ports:").grid(row=1, column=0, sticky="w")
        self.entry_ports = tk.Entry(frame_inputs, width=30)
        self.entry_ports.insert(0, "80,443")
        self.entry_ports.grid(row=1, column=1, sticky="w")

        tk.Label(frame_inputs, text="Policy file (optional):").grid(row=1, column=2, sticky="w", padx=(10,0))
        self.policy_path_var = tk.StringVar()
        tk.Entry(frame_inputs, textvariable=self.policy_path_var, width=30).grid(row=1, column=3, sticky="w")
        tk.Button(frame_inputs, text="Browse", command=self.browse_policy).grid(row=1, column=4, sticky="w", padx=(5,0))

        # Scan button
        tk.Button(root, text="Scan", command=self.start_scan).pack(pady=5)

        # Results Table
        self.tree = ttk.Treeview(root, columns=("Category", "Title", "Severity"), show="headings")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Title", text="Title")
        self.tree.heading("Severity", text="Severity")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        # Details Text
        tk.Label(root, text="Details:").pack(anchor="w", padx=10)
        self.text_details = tk.Text(root, height=10)
        self.text_details.pack(fill="x", padx=10, pady=(0,10))

        # Save Report button
        tk.Button(root, text="Save Report", command=self.save_report).pack(pady=(0,10))

        # Internal state
        self.findings = []
        self.report_paths = None

    def browse_policy(self):
        path = filedialog.askopenfilename(filetypes=[("JSON or YAML", "*.json *.yaml *.yml")])
        if path:
            self.policy_path_var.set(path)

    def start_scan(self):
        host = self.entry_host.get().strip()
        ports_str = self.entry_ports.get().strip()
        scheme = self.scheme_var.get()
        policy_file = self.policy_path_var.get() or None

        if not host:
            messagebox.showwarning("Input Error", "Please enter a host to scan.")
            return

        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        except ValueError:
            messagebox.showwarning("Input Error", "Ports must be comma-separated integers.")
            return

        self.tree.delete(*self.tree.get_children())
        self.text_details.delete("1.0", tk.END)
        self.findings = []

        # Run scan in a thread so GUI stays responsive
        threading.Thread(target=self.run_scan, args=(host, scheme, ports, policy_file), daemon=True).start()

    def run_scan(self, host, scheme, ports, policy_file):
        self.set_status("Loading policy...")
        policy = Policy.load(policy_file)
        engine = ScannerEngine(host, scheme, ports, policy)
        self.set_status("Scanning...")
        self.findings = engine.run()
        self.set_status(f"Scan completed: {len(self.findings)} findings")

        # Populate tree
        safe_host = sanitize_host_display(self.entry_host.get().strip())
        for i, f in enumerate(self.findings):
            icon = "✅" if f.severity.lower() == "low" else "❌"
            # Prepend icon to title for visual clarity
            self.tree.insert("", "end", iid=i, values=(f.category, f"{icon} {f.title}", f.severity))


        # Prepare report paths
        reporter = Reporter(REPORTS_DIR)
        self.report_paths = reporter.write(host, self.findings)

    def show_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        f = self.findings[idx]
        self.text_details.delete("1.0", tk.END)
        details = f"Category: {f.category}\nTitle: {f.title}\nSeverity: {f.severity}\n\n"
        details += f"Detection: {f.detection}\nExploitation: {f.exploitation}\nRemediation: {f.remediation}\n\n"
        if f.evidence:
            details += f"Evidence:\n{f.evidence}\n"
        self.text_details.insert(tk.END, details)

    def save_report(self):
        if not self.report_paths:
            messagebox.showinfo("No Reports", "No scan results to save yet.")
            return
        dest = filedialog.askdirectory(title="Select folder to copy reports")
        if not dest:
            return
        for path in self.report_paths:
            try:
                import shutil
                shutil.copy(path, dest)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy {path}: {e}")
        messagebox.showinfo("Saved", f"Reports copied to {dest}")

    def set_status(self, msg):
        self.root.title(f"Policy Web Scanner - {msg}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
