import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, conf
import os

# Callback function to process and display captured packets
def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        packet_info = f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}\n"
        packet_listbox.insert(tk.END, packet_info)

# Function to start packet capture
def start_capture():
    try:
        capture_button.config(state=tk.DISABLED)
        sniff(prn=packet_callback, count=int(packet_count_entry.get()))
    except RuntimeError as e:
        messagebox.showerror("Error", f"RuntimeError: {e}\nEnsure Npcap is installed.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    finally:
        capture_button.config(state=tk.NORMAL)

# Check if Npcap is installed
def check_npcap_installed():
    npcap_installed = False
    try:
        from scapy.arch.windows import get_windows_if_list
        if get_windows_if_list():
            npcap_installed = True
    except ImportError:
        pass
    return npcap_installed

# Set up the main application window
root = tk.Tk()
root.title("Network Packet Analyzer")

# Create and place the widgets
tk.Label(root, text="Number of packets to capture:").pack()
packet_count_entry = tk.Entry(root)
packet_count_entry.pack()
packet_count_entry.insert(0, "10")

capture_button = tk.Button(root, text="Start Capture", command=start_capture)
capture_button.pack()

packet_listbox = tk.Listbox(root, width=100, height=20)
packet_listbox.pack()

# Run the application
if check_npcap_installed():
    root.mainloop()
else:
    messagebox.showerror("Error", "Npcap is not installed. Please install Npcap and try again.")
