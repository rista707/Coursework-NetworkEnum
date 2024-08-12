import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import subprocess
import datetime
import customtkinter as ctk
from livehost import scan_network_arp, scan_network_icmp

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner GUI")
        self.results_text = ctk.CTkTextbox(self.root, wrap='word', state='normal', height=15)
        self.results_scroll = ctk.CTkScrollbar(self.root, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=self.results_scroll.set)
        
        self.center_window(800, 600)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"), background="#2e2e2e", foreground="#d3d3d3")
        self.style.configure("Treeview", font=("Helvetica", 12), rowheight=24, background="#2e2e2e", fieldbackground="#2e2e2e", foreground="#d3d3d3")
        self.style.map("Treeview", background=[("selected", "#3e3e3e")], foreground=[("selected", "white")])
        self.style.configure("TCombobox", font=("Helvetica", 12), padding=5)

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
        self.network_icon = ImageTk.PhotoImage(Image.open("icons/host_scan_icon.png").resize((40, 40)))
        self.title_label = ctk.CTkLabel(self.title_frame, text="  Host Scanning", image=self.network_icon, compound="left", font=("Helvetica", 24, "bold"))

        # Home icon
        self.home_icon = ImageTk.PhotoImage(Image.open("icons/home_icon.png").resize((30, 30)))
        self.home_button = ctk.CTkButton(self.title_frame, image=self.home_icon, text="", command=self.go_home, width=30, height=30)

        self.target_label = ctk.CTkLabel(self.root, text="IP Range")
        self.target_entry = ctk.CTkEntry(self.root, width=250)
        self.set_placeholder(self.target_entry, "e.g., 192.168.1.0/24")

        self.method_label = ctk.CTkLabel(self.root, text="Method")
        self.method_combobox = ttk.Combobox(self.root, values=["ARP", "ICMP"], state="readonly", width=15)
        self.method_combobox.current(0)
        self.method_combobox.bind("<<ComboboxSelected>>", self.method_selected)

        self.timeout_label = ctk.CTkLabel(self.root, text="Timeout")
        self.timeout_combobox = ttk.Combobox(self.root, values=[str(i) for i in range(1, 11)], state="readonly", width=15)
        self.timeout_combobox.current(1)

        self.retry_label = ctk.CTkLabel(self.root, text="Retry")
        self.retry_combobox = ttk.Combobox(self.root, values=[str(i) for i in range(1, 11)], state="readonly", width=15)
        self.retry_combobox.current(1)

        self.scan_button = ctk.CTkButton(self.root, text="Start Scan", command=self.start_scan)
        self.export_button = ctk.CTkButton(self.root, text="Export Results", command=self.export_results, width=80, height=25)

        # Treeview widget for displaying results
        self.treeview = ttk.Treeview(self.root, columns=("IP", "MAC"), show="headings", height=10)
        self.treeview.heading("IP", text="IP")
        self.treeview.heading("MAC", text="MAC")
        self.treeview.column("IP", width=200)
        self.treeview.column("MAC", width=400)
        self.treeview_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=self.treeview_scroll.set)

    def setup_layout(self):
        # Layout for title and home button
        self.title_frame.grid(column=0, row=0, columnspan=3, padx=10, pady=10, sticky='ew')
        self.title_label.grid(column=0, row=0, padx=10, pady=10, sticky='w')
        self.title_frame.grid_columnconfigure(1, weight=1)
        self.home_button.grid(column=2, row=0, padx=10, pady=10, sticky='e')

        self.target_label.grid(column=0, row=1, padx=10, pady=10, sticky='w')
        self.target_entry.grid(column=1, row=1, padx=10, pady=10, sticky='ew')

        self.method_label.grid(column=0, row=2, padx=10, pady=10, sticky='w')
        self.method_combobox.grid(column=1, row=2, padx=10, pady=10, sticky='ew')

        self.timeout_label.grid(column=0, row=3, padx=10, pady=10, sticky='w')
        self.timeout_combobox.grid(column=1, row=3, padx=10, pady=10, sticky='ew')

        self.retry_label.grid(column=0, row=4, padx=10, pady=10, sticky='w')
        self.retry_combobox.grid(column=1, row=4, padx=10, pady=10, sticky='ew')

        self.scan_button.grid(column=0, row=5, padx=10, pady=20, columnspan=2)
        self.export_button.grid(column=2, row=6, padx=10, pady=20, sticky='e')

        # Place Treeview widget
        self.treeview.grid(column=0, row=7, padx=10, pady=10, columnspan=3, sticky='nsew')
        self.treeview_scroll.grid(column=3, row=7, sticky='ns')

        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(7, weight=1)

    def set_placeholder(self, entry, placeholder):
        entry.insert(0, placeholder)
        entry.configure(text_color="#d3d3d3")
        entry.bind("<FocusIn>", lambda event: self.clear_placeholder(event, entry, placeholder))
        entry.bind("<FocusOut>", lambda event: self.add_placeholder(event, entry, placeholder))

    def clear_placeholder(self, event, entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            entry.configure(text_color="white")

    def add_placeholder(self, event, entry, placeholder):
        if not entry.get():
            entry.insert(0, placeholder)
            entry.configure(text_color="#d3d3d3")

    def method_selected(self, event):
        method = self.method_combobox.get()
        if method == "ICMP":
            self.retry_combobox.set("1")
            self.retry_combobox.configure(state="disabled")
        else:
            self.retry_combobox.configure(state="readonly")

    def start_scan(self):
        ip_range = self.target_entry.get().strip()
        method = self.method_combobox.get().lower()
        timeout = int(self.timeout_combobox.get())
        retry = int(self.retry_combobox.get())

        if not ip_range or ip_range == "e.g., 192.168.1.0/24":
            messagebox.showerror("Error", "Please enter a valid IP range.")
            return

        if method == "arp":
            live_hosts = scan_network_arp(ip_range, timeout=timeout, retry=retry)
        elif method == "icmp":
            live_hosts = scan_network_icmp(ip_range, timeout=timeout)

        # Clear previous treeview items
        for item in self.treeview.get_children():
            self.treeview.delete(item)

        # Populate Treeview with scanning output
        for host in live_hosts:
            self.treeview.insert("", tk.END, values=(host['ip'], host['mac']))

    def export_results(self):
        if not self.treeview.get_children():
            messagebox.showerror("Error", "No results to export.")
            return

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        default_filename = f"scan_results_{timestamp}.txt"
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_filename, filetypes=[("Text files", "*.txt"), ("All files", "*.*")])

        if file_path:
            try:
                with open(file_path, 'w') as file:
                    for item in self.treeview.get_children():
                        row = self.treeview.item(item)['values']
                        file.write(f"IP: {row[0]}, MAC: {row[1]}\n")
                messagebox.showinfo("Export Successful", f"Results exported to {file_path} successfully.")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred while exporting results: {str(e)}")

    def go_home(self):
        self.root.destroy()
        subprocess.Popen(["python", "main_home.py"])

def main():
    root = ctk.CTk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
