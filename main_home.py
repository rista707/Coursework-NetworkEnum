import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import subprocess  # To run external scripts

class HomePage:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Enumeration")
        self.center_window(600, 400)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.create_widgets()
        self.setup_layout()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        self.header_frame = ctk.CTkFrame(self.root, corner_radius=20, fg_color="#2e2e2e")
        self.header_label = ctk.CTkLabel(self.header_frame, text="Network Enumeration", font=("Helvetica", 28, "bold"))

        self.logo_label = ctk.CTkLabel(self.header_frame, text="🕸️", font=("Helvetica", 52))

        self.attack_frame = ctk.CTkFrame(self.root, corner_radius=20, fg_color="#3a3a3a")

        # Increase the size of the sword icon
        self.sword_icon = ImageTk.PhotoImage(Image.open("icons\\sword.png").resize((70, 50)))
        self.attack_label_with_icon = ctk.CTkLabel(self.attack_frame, text="Choose an Attack", image=self.sword_icon, compound="left", font=("Helvetica", 20, "bold"))

        # Icons for attacks
        self.port_enum_icon = ImageTk.PhotoImage(Image.open("icons\\port_enum_icon.png").resize((50, 50)))
        self.host_scan_icon = ImageTk.PhotoImage(Image.open("icons\\host_scan_icon.png").resize((50, 50)))
        self.domain_enum_icon = ImageTk.PhotoImage(Image.open("icons\\domain_enum_icon.png").resize((50, 50)))
        self.arp_poison_icon = ImageTk.PhotoImage(Image.open("icons\\arp_poison_icon.png").resize((50, 50)))

        self.port_enum_button = ctk.CTkButton(self.attack_frame, text="Port Enumeration", image=self.port_enum_icon, compound="left", command=self.port_enum, width=250, height=60, font=("Helvetica", 16))
        self.host_scan_button = ctk.CTkButton(self.attack_frame, text="Host Scanning", image=self.host_scan_icon, compound="left", command=self.host_scan, width=250, height=60, font=("Helvetica", 16))
        self.domain_enum_button = ctk.CTkButton(self.attack_frame, text="Domain Name Enumeration", image=self.domain_enum_icon, compound="left", command=self.domain_enum, width=250, height=60, font=("Helvetica", 16))
        self.arp_poison_button = ctk.CTkButton(self.attack_frame, text="ARP Poisoning", image=self.arp_poison_icon, compound="left", command=self.arp_poison, width=250, height=60, font=("Helvetica", 16))

    def setup_layout(self):
        self.header_frame.grid(column=0, row=0, padx=20, pady=10, sticky='ew')
        self.header_label.grid(column=0, row=0, padx=10, pady=10)
        self.logo_label.grid(column=1, row=0, padx=10, pady=10)

        self.attack_frame.grid(column=0, row=1, padx=20, pady=10, sticky='nsew')
        self.attack_label_with_icon.grid(column=0, row=0, padx=10, pady=10, columnspan=2, sticky='n')

        self.port_enum_button.grid(column=0, row=1, padx=10, pady=10, sticky='n')
        self.host_scan_button.grid(column=1, row=1, padx=10, pady=10, sticky='n')
        self.domain_enum_button.grid(column=0, row=2, padx=10, pady=10, sticky='n')
        self.arp_poison_button.grid(column=1, row=2, padx=10, pady=10, sticky='n')

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.attack_frame.grid_columnconfigure(0, weight=1)
        self.attack_frame.grid_columnconfigure(1, weight=1)
        self.attack_frame.grid_rowconfigure(0, weight=1)
        self.attack_frame.grid_rowconfigure(1, weight=1)
        self.attack_frame.grid_rowconfigure(2, weight=1)

    def port_enum(self):
        self.root.destroy()  # Close the main window
        subprocess.Popen(["python", "win_port.py"])  # Run the win_port.py script

    def host_scan(self):
        self.root.destroy() 
        subprocess.Popen(["python", "live_host_win.py"])

    def domain_enum(self):
        self.root.destroy()
        subprocess.Popen(["python", "win_dns.py"])

    def arp_poison(self):
        messagebox.showinfo("Info", "Future Work, On Progress")


def main():
    root = ctk.CTk()
    app = HomePage(root)
    root.mainloop()

if __name__ == "__main__":
    main()
