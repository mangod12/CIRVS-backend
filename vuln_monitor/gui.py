import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import yaml
import logging
import os
import sys
import threading

# Add the parent directory to the Python path for module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_monitor.config import load_config
from vuln_monitor.main import run_monitor

# Save the target email address to the configuration file
def save_target_address(entry_widget, output_text):
    """Save the target email address to configuration."""
    new_address = entry_widget.get().strip()
    if not new_address:
        messagebox.showerror("Error", "Please enter a valid email address!")
        return
    try:
        config = load_config()
        if 'email' not in config:
            config['email'] = {}
        config['email']['recipients'] = [new_address]
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'configs', 'settings.yaml')
        with open(config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
        output_text.insert(tk.END, f"✓ Target address updated to: {new_address}\n")
        output_text.see(tk.END)
        messagebox.showinfo("Success", "Target address updated successfully!")
    except Exception as e:
        error_msg = f"Failed to update target address: {e}"
        output_text.insert(tk.END, f"✗ {error_msg}\n")
        output_text.see(tk.END)
        messagebox.showerror("Error", error_msg)

# Display the vulnerability report in the GUI in a human-readable format
def show_report_in_gui(vulns, output_text):
    """Display the vulnerability report in the GUI."""
    output_text.delete(1.0, tk.END)
    if not vulns:
        output_text.insert(tk.END, "No vulnerabilities found.\n")
        return
    output_text.insert(tk.END, f"Vulnerability Report\n{'='*80}\n")
    for i, vuln in enumerate(vulns, 1):
        output_text.insert(tk.END, f"{i}. Product Name: {vuln.get('Product Name', 'N/A')}\n")
        output_text.insert(tk.END, f"   Product Version: {vuln.get('Product Version', 'NA')}\n")
        output_text.insert(tk.END, f"   OEM Name: {vuln.get('OEM Name', 'N/A')}\n")
        output_text.insert(tk.END, f"   Severity Level: {vuln.get('Severity Level', 'N/A')}\n")
        output_text.insert(tk.END, f"   Vulnerability: {vuln.get('Vulnerability', 'N/A')}\n")
        output_text.insert(tk.END, f"   Mitigation Strategy: {vuln.get('Mitigation Strategy', 'N/A')}\n")
        output_text.insert(tk.END, f"   Published Date: {vuln.get('Published Date', 'N/A')}\n")
        output_text.insert(tk.END, f"   Unique ID: {vuln.get('Unique ID', 'N/A')}\n")
        # Show CVE details if available
        if 'CVE Details' in vuln and isinstance(vuln['CVE Details'], dict):
            cve = vuln['CVE Details']
            output_text.insert(tk.END, f"   CVE Description: {cve.get('description', 'N/A')}\n")
            output_text.insert(tk.END, f"   CVE Published: {cve.get('published', 'N/A')}\n")
            output_text.insert(tk.END, f"   CVE Modified: {cve.get('modified', 'N/A')}\n")
        output_text.insert(tk.END, '-'*80 + '\n')

# Start vulnerability monitoring in a separate thread and update the GUI with the report
def start_monitor_with_gui(output_text, root, websites_entry):
    """Start vulnerability monitoring in a separate thread."""
    def monitor_thread():
        try:
            output_text.insert(tk.END, "Starting vulnerability monitoring...\n")
            output_text.see(tk.END)
            root.update()
            # Get websites from input
            websites_text = websites_entry.get("1.0", tk.END).strip()
            websites = [url.strip() for url in websites_text.split('\n') if url.strip()]
            if websites:
                output_text.insert(tk.END, f"Scanning {len(websites)} websites:\n")
                for url in websites:
                    output_text.insert(tk.END, f"  - {url}\n")
                output_text.see(tk.END)
            # Setup logging to capture output
            logger = logging.getLogger("vuln_monitor")
            # Run the monitor
            vulns, report_path = run_monitor(websites)
            show_report_in_gui(vulns, output_text)
            output_text.insert(tk.END, f"\n✓ Vulnerability monitoring completed successfully!\n")
            output_text.insert(tk.END, f"✓ Found {len(vulns)} vulnerabilities\n")
            if report_path:
                output_text.insert(tk.END, f"✓ Report saved at: {report_path}\n")
            # Display vulnerability summary
            if vulns:
                output_text.insert(tk.END, "\n--- Vulnerability Summary ---\n")
                severity_count = {}
                for vuln in vulns:
                    severity = vuln.get('Severity Level', 'Unknown')
                    severity_count[severity] = severity_count.get(severity, 0) + 1
                for severity, count in severity_count.items():
                    output_text.insert(tk.END, f"{severity}: {count} vulnerabilities\n")
            output_text.see(tk.END)
            # Show success message in main thread
            success_msg = f"Vulnerability monitoring completed successfully!\nFound {len(vulns)} vulnerabilities"
            if report_path:
                success_msg += f"\nReport saved at: {report_path}"
            root.after(0, lambda: messagebox.showinfo("Success", success_msg))
        except Exception as e:
            error_msg = f"Error during monitoring: {e}"
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, f"✗ {error_msg}\n")
            root.after(0, lambda: messagebox.showerror("Error", f"Failed to complete monitoring: {e}"))
    # Start monitoring in a separate thread to prevent GUI freezing
    thread = threading.Thread(target=monitor_thread, daemon=True)
    thread.start()

# Create and run the main GUI application
def create_gui():
    """Create and run the main GUI application."""
    root = tk.Tk()
    root.title("Vulnerability Monitor GUI")
    root.geometry("900x700")
    # Create main frame
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    # Email configuration section
    email_frame = tk.LabelFrame(main_frame, text="Email Configuration", padx=10, pady=10)
    email_frame.pack(fill=tk.X, pady=(0, 10))
    tk.Label(email_frame, text="Target Email Address:").pack(anchor=tk.W)
    email_entry = tk.Entry(email_frame, width=60)
    email_entry.pack(fill=tk.X, pady=(5, 10))
    # Websites input section
    websites_frame = tk.LabelFrame(main_frame, text="Websites to Scan (one per line)", padx=10, pady=10)
    websites_frame.pack(fill=tk.X, pady=(0, 10))
    websites_entry = tk.Text(websites_frame, height=5, width=80)
    websites_entry.pack(fill=tk.X, pady=(5, 10))
    # Output section
    output_frame = tk.LabelFrame(main_frame, text="Output Log", padx=10, pady=10)
    output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
    output_text.pack(fill=tk.BOTH, expand=True)
    # Buttons section
    button_frame = tk.Frame(main_frame)
    button_frame.pack(fill=tk.X)
    save_btn = tk.Button(button_frame, text="Save Email Address", 
                        command=lambda: save_target_address(email_entry, output_text),
                        bg="#4CAF50", fg="white", padx=20)
    save_btn.pack(side=tk.LEFT, padx=(0, 10))
    monitor_btn = tk.Button(button_frame, text="Start Monitoring", 
                           command=lambda: start_monitor_with_gui(output_text, root, websites_entry),
                           bg="#2196F3", fg="white", padx=20)
    monitor_btn.pack(side=tk.LEFT, padx=(0, 10))
    clear_btn = tk.Button(button_frame, text="Clear Log", 
                         command=lambda: output_text.delete(1.0, tk.END),
                         bg="#FF9800", fg="white", padx=20)
    clear_btn.pack(side=tk.LEFT)
    # Initial log message
    output_text.insert(tk.END, "Vulnerability Monitor GUI Started\n")
    output_text.insert(tk.END, "Please configure your email address, enter websites, and start monitoring.\n\n")
    root.mainloop()

# Entry point for running the GUI
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    create_gui()
