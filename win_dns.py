import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import threading
import subprocess
from datetime import datetime
import dns_enum_backend

class DNSEnumGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Enumeration Tool")
        self.center_window(1000, 800)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"), background="#2e2e2e", foreground="#d3d3d3")
        self.style.configure("Treeview", font=("Helvetica", 12), rowheight=24, background="#2e2e2e", fieldbackground="#2e2e2e", foreground="#d3d3d3")
        self.style.map("Treeview", background=[("selected", "#3e3e3e")], foreground=[("selected", "white")])

        self.create_widgets()
        self.setup_layout()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        # Title with icon
        self.title_frame = ctk.CTkFrame(self.root, corner_radius=20, fg_color="#2e2e2e")
        self.dns_enum_icon = ImageTk.PhotoImage(Image.open("icons/domain_enum_icon.png").resize((40, 40)))
        self.title_label = ctk.CTkLabel(self.title_frame, text="  DNS Enumeration", image=self.dns_enum_icon, compound="left", font=("Helvetica", 24, "bold"))

        # Home icon
        self.home_icon = ImageTk.PhotoImage(Image.open("icons/home_icon.png").resize((30, 30)))
        self.home_button = ctk.CTkButton(self.title_frame, image=self.home_icon, text="", command=self.go_home, width=30, height=30)

        self.target_label = ctk.CTkLabel(self.root, text="Target Domain / IP")
        self.target_entry = ctk.CTkEntry(self.root, width=300)
        self.set_placeholder(self.target_entry, "e.g., 192.168.1.1 or example.com")

        self.wordlist_label = ctk.CTkLabel(self.root, text="Subdomain Wordlist (Optional)")
        self.wordlist_entry = ctk.CTkEntry(self.root, width=300)
        self.set_placeholder(self.wordlist_entry, "e.g., subdomains.txt")

        self.enum_subdomains_var = tk.BooleanVar()
        self.enum_subdomains_check = ctk.CTkCheckBox(self.root, text="Subdomains", variable=self.enum_subdomains_var, width=150)

        self.enum_dns_var = tk.BooleanVar()
        self.enum_dns_check = ctk.CTkCheckBox(self.root, text="DNS Records", variable=self.enum_dns_var, width=150)

        self.reverse_dns_var = tk.BooleanVar()
        self.reverse_dns_check = ctk.CTkCheckBox(self.root, text="Reverse DNS", variable=self.reverse_dns_var, width=150)

        self.enum_srv_var = tk.BooleanVar()
        self.enum_srv_check = ctk.CTkCheckBox(self.root, text="SRV Records", variable=self.enum_srv_var, width=150)

        self.zone_transfer_var = tk.BooleanVar()
        self.zone_transfer_check = ctk.CTkCheckBox(self.root, text="Zone Transfer", variable=self.zone_transfer_var, width=150)

        self.whois_var = tk.BooleanVar()
        self.whois_check = ctk.CTkCheckBox(self.root, text="WHOIS Info", variable=self.whois_var, width=150)

        self.start_button = ctk.CTkButton(self.root, text="Start Enumeration", command=self.start_enumeration, width=150)
        self.export_button = ctk.CTkButton(self.root, text="Export Results", command=self.export_results, width=150, height=25)

        self.log_text = ctk.CTkTextbox(self.root, wrap='word', state='disabled', height=50)
        self.log_scroll = ctk.CTkScrollbar(self.root, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scroll.set)

        self.result_tree = ttk.Treeview(self.root, columns=("Type", "Result"), show='headings', height=50)
        self.result_tree.heading("Type", text="Type")
        self.result_tree.heading("Result", text="Result")
        self.result_scroll = ctk.CTkScrollbar(self.root, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=self.result_scroll.set)

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
        self.title_frame.grid(column=0, row=0, columnspan=4, padx=10, pady=10, sticky='ew')
        self.title_label.grid(column=0, row=0, padx=10, pady=10, sticky='w')
        self.title_frame.grid_columnconfigure(2, weight=1)
        self.home_button.grid(column=3, row=0, padx=10, pady=10, sticky='e')

        self.target_label.grid(column=0, row=1, padx=10, pady=10, sticky='w')
        self.target_entry.grid(column=1, row=1, padx=10, pady=10, sticky='ew')

        self.wordlist_label.grid(column=2, row=1, padx=10, pady=10, sticky='w')
        self.wordlist_entry.grid(column=3, row=1, padx=10, pady=10, sticky='ew')

        self.enum_subdomains_check.grid(column=1, row=2, padx=10, pady=5, sticky='w')
        self.enum_dns_check.grid(column=2, row=2, padx=10, pady=5, sticky='w')
        self.reverse_dns_check.grid(column=3, row=2, padx=10, pady=5, sticky='w')

        self.zone_transfer_check.grid(column=1, row=3, padx=10, pady=5, sticky='w')
        self.whois_check.grid(column=2, row=3, padx=10, pady=5, sticky='w')
        self.enum_srv_check.grid(column=3, row=3, padx=10, pady=5, sticky='w')

        self.start_button.grid(column=0, row=4, padx=10, pady=10, columnspan=4, sticky='ew')

        self.result_tree.grid(column=0, row=5, padx=10, pady=10, columnspan=4, sticky='nsew')
        self.result_scroll.grid(column=4, row=5, sticky='ns')

        self.export_button.grid(column=0, row=6, padx=10, pady=10, columnspan=4, sticky='ew')

        self.log_text.grid(column=0, row=7, padx=10, pady=5, columnspan=4, sticky='ew')
        self.log_scroll.grid(column=4, row=7, sticky='ns')

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(2, weight=1)
        self.root.grid_columnconfigure(3, weight=1)
        self.root.grid_rowconfigure(5, weight=1)
        self.root.grid_rowconfigure(7, weight=0)

    def start_enumeration(self):
        target = self.target_entry.get()
        wordlist = self.wordlist_entry.get() if self.wordlist_entry.get() != "e.g., subdomains.txt" else None

        if not target or target == "e.g., 192.168.1.1 or example.com":
            messagebox.showerror("Error", "Please enter a valid target domain or IP.")
            return

        if not (self.enum_subdomains_var.get() or self.enum_dns_var.get() or self.reverse_dns_var.get() or
                self.enum_srv_var.get() or self.zone_transfer_var.get() or self.whois_var.get()):
            messagebox.showerror("Error", "Please select at least one enumeration option.")
            return

        self.result_tree.delete(*self.result_tree.get_children())
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, 'end')
        self.log_text.insert('end', f"Starting enumeration on {target} at {datetime.now()}\n")
        self.log_text.configure(state='disabled')

        threading.Thread(target=self.run_enumeration, args=(target, wordlist)).start()

    def run_enumeration(self, target, wordlist):
        if self.enum_subdomains_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Enumerating subdomains...\n")
            self.log_text.configure(state='disabled')
            subdomains = dns_enum_backend.enum_subdomains(target, wordlist)
            for subdomain in subdomains:
                self.result_tree.insert("", "end", values=("Subdomain", subdomain))

        if self.enum_dns_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Enumerating DNS records...\n")
            self.log_text.configure(state='disabled')
            dns_records = dns_enum_backend.enum_dns_records(target)
            for record_type, records in dns_records.items():
                for record in records:
                    self.result_tree.insert("", "end", values=(record_type, record))

        if self.reverse_dns_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Performing reverse DNS lookup...\n")
            self.log_text.configure(state='disabled')
            ip_address = dns_enum_backend.get_ip_address(target)
            if ip_address:
                reverse_domain = dns_enum_backend.reverse_dns_lookup(ip_address)
                self.result_tree.insert("", "end", values=("Reverse DNS", reverse_domain))

        if self.enum_srv_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Enumerating SRV records...\n")
            self.log_text.configure(state='disabled')
            srv_records = dns_enum_backend.enum_srv_records(target)
            for service, records in srv_records.items():
                if records:
                    for record in records:
                        self.result_tree.insert("", "end", values=(service, record))
                else:
                    self.result_tree.insert("", "end", values=(service, f"No {service} SRV records found for {target}"))

        if self.zone_transfer_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Attempting zone transfer...\n")
            self.log_text.configure(state='disabled')
            zone_records = dns_enum_backend.zone_transfer(target)
            if isinstance(zone_records, dict):
                for name, records in zone_records.items():
                    for record in records:
                        self.result_tree.insert("", "end", values=(name, record))
            else:
                self.result_tree.insert("", "end", values=("Zone Transfer", zone_records))

        if self.whois_var.get():
            self.log_text.configure(state='normal')
            self.log_text.insert('end', "Retrieving WHOIS information...\n")
            self.log_text.configure(state='disabled')
            domain_info = dns_enum_backend.whois_info(target)
            self.display_whois_info(domain_info)

        self.log_text.configure(state='normal')
        self.log_text.insert('end', "Enumeration completed.\n")
        self.log_text.configure(state='disabled')

    def display_whois_info(self, domain_info):
        if isinstance(domain_info, dict):
            for key, value in domain_info.items():
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                elif isinstance(value, datetime):
                    value = value.strftime("%Y-%m-%d %H:%M:%S")
                self.result_tree.insert("", "end", values=(key, value))
        else:
            self.result_tree.insert("", "end", values=("WHOIS", domain_info))

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
    app = DNSEnumGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
