import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
from collections import defaultdict

class LogProcessor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = defaultdict(list)
    
    def read_log(self):
        try:
            with open(self.file_path, 'r') as file:
                return file.readlines()
        except FileNotFoundError:
            return []
    
    def process(self):
        raise NotImplementedError("Subclasses must implement this method")

class AuthLogProcessor(LogProcessor):
    def process(self):
        self.data.clear()
        for line in self.read_log():
            if "Failed password" in line:
                match = re.search(r'Failed password for (.+?) from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    self.data['Failed Attempts'].append((match.group(1), match.group(2)))
            elif "Accepted password" in line:
                match = re.search(r'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    self.data['Successful Logins'].append((match.group(1), match.group(2)))
        return self.data

class SysLogProcessor(LogProcessor):
    def process(self):
        self.data.clear()
        error_keywords = ["failed", "error", "critical", "warning", "disk usage", "memory usage", "stopped"]
        
        for line in self.read_log():
            normalized_line = line.strip().lower()
            if any(keyword in normalized_line for keyword in error_keywords):
                self.data['System Alerts'].append(line.strip())
        
        return self.data



class FirewallLogProcessor(LogProcessor):
    def process(self):
        self.data.clear()
        for line in self.read_log():
            if "UFW BLOCK" in line:
                match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    self.data['Blocked IPs'].append(match.group(1))
        return self.data

class WebServerLogProcessor(LogProcessor):
    def process(self):
        self.data.clear()
        for line in self.read_log():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+) - - \[.+\] \"(GET|POST) (.+?)\"', line)
            if match:
                self.data['Access Attempts'].append((match.group(1), match.group(2), match.group(3)))
        return self.data

class NetworkLogProcessor(LogProcessor):
    def process(self):
        self.data.clear()
        for line in self.read_log():
            match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+) PROTO=(TCP|UDP) DPT=(\d+)', line)
            if match:
                self.data['Network Connections'].append((match.group(1), match.group(2), match.group(3), match.group(4)))
        return self.data

class LogAnalyzer:
    def __init__(self, processor):
        self.processor = processor
    
    def analyze(self):
        return self.processor.process()

class LogGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Processor GUI")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f0f0")
        
        self.log_types = {
            "auth": AuthLogProcessor,
            "syslog": SysLogProcessor,
            "firewall": FirewallLogProcessor,
            "web": WebServerLogProcessor,
            "network": NetworkLogProcessor
        }
        
        self.file_path = None

        self.frame = ttk.Frame(root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(self.frame, text="Select Log Type:", font=("Arial", 12)).pack(pady=5)
        
        self.log_type_var = tk.StringVar(value="auth")
        self.dropdown = ttk.Combobox(self.frame, textvariable=self.log_type_var, values=list(self.log_types.keys()))
        self.dropdown.pack(pady=5)
        
        self.file_button = ttk.Button(self.frame, text="Browse Log File", command=self.browse_file)
        self.file_button.pack(pady=5)
        
        self.process_button = ttk.Button(self.frame, text="Process Log", command=self.process_log)
        self.process_button.pack(pady=5)
        
        self.text_area = scrolledtext.ScrolledText(self.frame, height=15, width=70, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(pady=5, padx=5)
    
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.process_log()
    
    def process_log(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        selected_log_type = self.log_type_var.get()  # User-selected type

        # Read first few lines for better detection
        with open(self.file_path, 'r') as file:
            first_lines = [file.readline().lower() for _ in range(5)]  # Read first 5 lines

        # Keywords to differentiate logs
        auth_keywords = ["failed password", "accepted password"]
        syslog_keywords = ["error", "Failed", "systemd", "auditd"]
        firewall_keywords = ["firewalld", "iptables", "ufw", "ufw block", "firewall rule"]
        web_keywords = ["nginx", "apache", "http/1.1", "403 forbidden", "404 not found", "get", "post"]
        network_keywords = ["dhcp", "arp", "icmp", "tcpdump", "src=", "dst=", "proto=", "dpt="]

        auth_count = sum(1 for line in first_lines if any(keyword in line for keyword in auth_keywords))
        syslog_count = sum(1 for line in first_lines if any(keyword in line for keyword in syslog_keywords))

        # Determine log type
        if auth_count > 0 and syslog_count == 0:  
            detected_log_type = "auth"  # Pure auth logs
        elif syslog_count > 0:  
            detected_log_type = "syslog"  # Mixed system logs
        elif any(keyword in line for keyword in firewall_keywords for line in first_lines):
            detected_log_type = "firewall"
        elif any(keyword in line for keyword in web_keywords for line in first_lines):
            detected_log_type = "web"
        elif any(keyword in line for keyword in network_keywords for line in first_lines):  # Check keywords first
            detected_log_type = "network"
        elif any(re.search(r'SRC=\d+\.\d+\.\d+\.\d+ DST=\d+\.\d+\.\d+\.\d+', line) for line in first_lines):
            detected_log_type = "network"
        else:
            messagebox.showerror("Error", "Could not determine the log type. Please select the correct type manually.")
            return

        # Notify if switching log type
        if detected_log_type != selected_log_type:
            messagebox.showinfo("Log Type Changed", 
                                f"Selected log type '{selected_log_type}' does not match the file contents.\n"
                                f"Automatically switching to '{detected_log_type}'.")

        self.log_type_var.set(detected_log_type)  # Update dropdown selection

        try:
            self.text_area.delete(1.0, tk.END)
            processor = self.log_types[detected_log_type](self.file_path)
            analyzer = LogAnalyzer(processor)
            results = analyzer.analyze()

            if not results:
                raise ValueError("No relevant log entries found.")

            self.display_results(results)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to process log: {str(e)}")


    def display_results(self, results):
        self.text_area.delete(1.0, tk.END)
        for key, values in results.items():
            self.text_area.insert(tk.END, f"{key}:\n")
            for value in values:
                self.text_area.insert(tk.END, f"  {value}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogGUI(root)
    root.mainloop()
