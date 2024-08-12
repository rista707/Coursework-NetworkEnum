import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import threading
import ipaddress
import validators
from datetime import datetime
import subprocess  # To run external scripts
from port_backend import PortScanner  # Ensure your original script is saved as port_scanner.py

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.center_window(800, 600)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"), background="#2e2e2e", foreground="#d3d3d3")
        self.style.configure("Treeview", font=("Helvetica", 12), rowheight=24, background="#2e2e2e", fieldbackground="#2e2e2e", foreground="#d3d3d3")
        self.style.map("Treeview", background=[("selected", "#3e3e3e")], foreground=[("selected", "white")])

        self.create_widgets()
        self.setup_layout()

        self.port_info = {}  # Dictionary to store port info to avoid duplicates
        self.os_info = None  # Variable to store OS detection info
        self.start_time = None  # Variable to store start time of scan

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        # Title with icon
        self.title_frame = ctk.CTkFrame(self.root, corner_radius=20, fg_color="#2e2e2e")
        self.port_enum_icon = ImageTk.PhotoImage(Image.open("icons/port_enum_icon.png").resize((40, 40)))
        self.title_label = ctk.CTkLabel(self.title_frame, text="  Port Scanner", image=self.port_enum_icon, compound="left", font=("Helvetica", 24, "bold"))

        # Home icon
        self.home_icon = ImageTk.PhotoImage(Image.open("icons/home_icon.png").resize((30, 30)))
        self.home_button = ctk.CTkButton(self.title_frame, image=self.home_icon, text="", command=self.go_home, width=30, height=30)

        self.target_label = ctk.CTkLabel(self.root, text="Target IP / Host")
        self.target_entry = ctk.CTkEntry(self.root, width=250)
        self.set_placeholder(self.target_entry, "e.g., 192.168.1.1 or example.com")

        self.port_label = ctk.CTkLabel(self.root, text="Ports")
        self.port_entry = ctk.CTkEntry(self.root, width=250)
        self.set_placeholder(self.port_entry, "e.g., 80, 1-100")

        self.os_detect_var = tk.BooleanVar()
        self.os_detect_check = ctk.CTkCheckBox(self.root, text="Enable OS Detection", variable=self.os_detect_var, command=self.toggle_os_row)

        self.start_button = ctk.CTkButton(self.root, text="Start Scan", command=self.start_scan)
        self.export_button = ctk.CTkButton(self.root, text="Export Results", command=self.export_results, width=80, height=25)

        self.log_text = ctk.CTkTextbox(self.root, wrap='word', state='disabled', height=200)
        self.log_scroll = ctk.CTkScrollbar(self.root, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scroll.set)

        self.result_tree = ttk.Treeview(self.root, columns=("Port", "Service", "Version"), show='headings', height=15)
        self.result_tree.heading("Port", text="Port")
        self.result_tree.heading("Service", text="Service")
        self.result_tree.heading("Version", text="Version")
        self.result_scroll = ctk.CTkScrollbar(self.root, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=self.result_scroll.set)

        self.os_label = ctk.CTkLabel(self.root, text="", font=("Helvetica", 12))

    def set_placeholder(self, entry, placeholder):
        entry.insert(0, placeholder)
        entry.configure(text_color="#d3d3d3")  # Use a color that matches the label's color
        entry.bind("<FocusIn>", lambda event: self.clear_placeholder(event, entry, placeholder))
        entry.bind("<FocusOut>", lambda event: self.add_placeholder(event, entry, placeholder))

    def clear_placeholder(self, event, entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            entry.configure(text_color="white")  # Set text color to match normal input color

    def add_placeholder(self, event, entry, placeholder):
        if not entry.get():
            entry.insert(0, placeholder)
            entry.configure(text_color="#d3d3d3")  # Use a color that matches the label's color

    def setup_layout(self):
        # Layout for title and home button
        self.title_frame.grid(column=0, row=0, columnspan=3, padx=10, pady=10, sticky='ew')
        self.title_label.grid(column=0, row=0, padx=10, pady=10, sticky='w')
        self.title_frame.grid_columnconfigure(1, weight=1)
        self.home_button.grid(column=2, row=0, padx=10, pady=10, sticky='e')

        self.target_label.grid(column=0, row=1, padx=10, pady=10, sticky='w')
        self.target_entry.grid(column=1, row=1, padx=10, pady=10, sticky='ew')

        self.port_label.grid(column=0, row=2, padx=10, pady=10, sticky='w')
        self.port_entry.grid(column=1, row=2, padx=10, pady=10, sticky='ew')

        self.os_detect_check.grid(column=0, row=3, padx=10, pady=10, sticky='w')

        self.start_button.grid(column=0, row=4, padx=10, pady=20, columnspan=2)

        self.os_label.grid(column=0, row=5, padx=10, pady=10, columnspan=2, sticky='w')
        self.os_label.grid_remove()  # Initially hidden

        self.result_tree.grid(column=0, row=6, padx=10, pady=10, columnspan=2, sticky='nsew')
        self.result_scroll.grid(column=2, row=6, sticky='ns')

        self.export_button.grid(column=0, row=7, padx=10, pady=10, columnspan=2)

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(6, weight=1)
        self.root.grid_rowconfigure(7, weight=0)

    def toggle_os_row(self):
        if self.os_detect_var.get():
            self.os_label.grid()
        else:
            self.os_label.grid_remove()

    def start_scan(self):
        target = self.target_entry.get()
        ports = self.port_entry.get()
        os_detect = self.os_detect_var.get()

        if not self.validate_target(target):
            messagebox.showerror("Error", "Please enter a valid IPv4 address or domain name.")
            return

        if not ports or ports == "e.g., 80, 1-100":
            ports = "1-1000"  # Default to the first 1000 ports

        if not self.validate_ports(ports):
            messagebox.showerror("Error", "Please enter a valid port range (0-65535).")
            return

        self.result_tree.delete(*self.result_tree.get_children())
        self.port_info.clear()  # Clear previous scan data
        self.os_info = None
        self.os_label.configure(text="")
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, 'end')
        self.log_text.insert('end', f"Starting scan on {target} at {datetime.now()}\n")
        self.log_text.configure(state='disabled')

        self.start_time = datetime.now()

        threading.Thread(target=self.run_scan, args=(target, ports, os_detect)).start()

    def validate_target(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return validators.domain(target)

    def validate_ports(self, ports):
        if ',' in ports:
            port_list = ports.split(',')
        else:
            port_list = [ports]

        for port_range in port_list:
            if '-' in port_range:
                start, end = port_range.split('-')
                if not (start.isdigit() and end.isdigit()):
                    return False
                if not (0 <= int(start) <= 65535 and 0 <= int(end) <= 65535):
                    return False
            else:
                if not port_range.isdigit():
                    return False
                if not (0 <= int(port_range) <= 65535):
                    return False

        return True

    def run_scan(self, target, ports, os_detect):
        scanner = PortScanner(target, ports, os_detect, self.update_log)
        scanner.scan()

        end_time = datetime.now()
        time_taken = end_time - self.start_time
        self.update_log(f"Scan Completed\nTime Taken: {time_taken}")

    def update_log(self, message):
        if message.startswith("Port "):
            parts = message.split()
            port = parts[1]
            service = parts[3]
            version = ' '.join(parts[5:]) if len(parts) > 5 else 'Unknown'
            if service != "Unknown" and version != "Unknown":
                self.result_tree.insert("", "end", values=(port, service, version))
        elif message.startswith("OS Detection:"):
            self.os_info = message.split(": ")[1]
            self.os_label.configure(text=f"OS Detection: {self.os_info}")
        elif message.startswith("Scan Completed"):
            # Insert a row that spans all columns
            self.result_tree.insert("", "end", values=("", "", ""))
            self.result_tree.insert("", "end", values=(message.replace("\n", " | "), "", ""), tags=("completed",))
            self.result_tree.tag_configure("completed", background="lightgreen", font=("Helvetica", 12, "bold"), foreground="black")
        else:
            self.log_text.configure(state='normal')
            self.log_text.insert('end', message + "\n")
            self.log_text.see('end')
            self.log_text.configure(state='disabled')

    def export_results(self):
        if not self.result_tree.get_children():
            messagebox.showinfo("Export", "Nothing to Export")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".tsv", filetypes=[("TSV files", "*.tsv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w', newline='') as file:
                for row_id in self.result_tree.get_children():
                    row = self.result_tree.item(row_id)['values']
                    file.write("\t".join(map(str, row)) + "\n")
            messagebox.showinfo("Export", f"Results successfully exported to {file_path}")

    def go_home(self):
        self.root.destroy()  # Close the current window
        subprocess.Popen(["python", "main_home.py"])  # Open the main.py script

def main():
    root = ctk.CTk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()