# The Network Packet Analyzer
## Project Description
The Network Packet Analyzer is a tool developed to capture and analyze network packets. It provides detailed information about each packet, such as source and destination IP addresses, protocols, and payload data. This tool is useful for educational purposes, enabling users to learn about network traffic, protocols, and packet structures.

## Key Features
### Packet Capturing:

Utilizes the Scapy library to capture network packets.
Displays relevant information such as source IP, destination IP, and protocol type.
### Packet Analysis:

Extracts and analyzes data from each captured packet.
Provides detailed packet information in a readable format.
### User Interface:

A Tkinter-based GUI to display captured packet information.
Allows users to specify the number of packets to capture.
Implementation Details
### Python and Scapy:

The core functionality of capturing and analyzing packets is handled by the Scapy library.
Scapy provides powerful capabilities for network packet manipulation and analysis.
Tkinter for GUI:

The Tkinter library is used to create a user-friendly graphical interface.
Users can start packet capture, specify the number of packets, and view the captured packets in a listbox.
### Npcap for Windows:

Npcap is required for packet capturing on Windows.
The script includes error handling to ensure Npcap is installed and provides appropriate error messages if not.Npcap is the Nmap Project's packet capture (and sending) library for Microsoft Windows. It implements the open Pcap API using a custom Windows kernel driver alongside our Windows build of the excellent libpcap library. This allows Windows software to capture raw network traffic (including wireless networks, wired ethernet, localhost traffic, and many VPNs) using a simple, portable API. Npcap allows for sending raw packets as well. Mac and Linux systems already include the Pcap API, so Npcap allows popular software such as Nmap and Wireshark to run on all these platforms (and more) with a single codebase. Npcap began in 2013 as some improvements to the (now discontinued) WinPcap library, but has been largely rewritten since then with hundreds of releases improving Npcap's speed, portability, security, and efficiency.

## Running the Project
### Install Npcap:

Download and install Npcap from the Npcap website.
Ensure to install it in WinPcap API-compatible mode.
### Run the Script:

Open Command Prompt as an administrator.
Navigate to the directory containing the script.
Execute the script using
#### python new.py
Interact with the GUI:

Specify the number of packets to capture in the input field.
Click "Start Capture" to begin packet capture.
View the captured packet information in the listbox.
Ethical Considerations
Usage: This tool should only be used for educational purposes on networks where you have permission to monitor traffic.
##### Legal Compliance: Unauthorized packet sniffing is illegal and unethical. 
Always ensure you have the necessary permissions before capturing network traffic.
This project helps users understand network protocols, analyze network traffic, and learn about packet structures through hands-on experience.
