import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import threading
import subprocess
import os

class DDoSPreventer:
    def __init__(self):
        self.request_limit = 100  # Maximum allowed requests per IP
        self.check_interval = 10  # Time interval for checking traffic (in seconds)
        self.block_remover = 1800 # timer to unblock ip from blacklist
        self.ip_counter = defaultdict(int)  # Dictionary to count requests per IP
        self.whitelist_ip_file = "whitelisted_ips.txt"  # List of trusted IPs that won't be blocked
        self.blocked_ips_file = "blocked_ips.txt"  # File to store blocked IPs

        # Reload previously blocked IPs from file
        self.reload_blocked_ips()

        # Start the background monitoring thread
        self.monitor_thread = threading.Thread(target=self.request_counter, daemon=True)
        self.monitor_thread.start()

    def reload_blocked_ips(self):
        """Reload previously blocked IPs from the file and reapply iptables rules."""
        with open(self.blocked_ips_file, "a") as file:
            for line in file:
                    ip = line.strip()
                if ip:
                    self.block_ip(ip, log=False)  # Reapply iptables rule without logging
        print("[*] Reloaded blocked IPs from file.")

    def packet_catch(self, packet):
        """Capture network packets and count requests from each IP."""
        if packet.haslayer(IP):
            ip_source = packet[IP].src
            
            if packet.haslayer(TCP):
                print(f"[TCP] Paket alındı: {ip_source}")
            elif packet.haslayer(UDP):
                print(f"[UDP] Paket alındı: {ip_source}")
            elif packet.haslayer(ICMP):
                print(f"[ICMP] Paket alındı: {ip_source}")

            if ip_source in self.blacklist:
                return
            # Skip counting for whitelisted IPs
            if ip_source in self.whitelist:
                return  

            self.ip_counter[ip_source] += 1

    def remove_last_line(self):
        """Remove the last line from the blocked_ips.txt file."""
        time.sleep(self.block_remover)
        with open(self.blocked_ips_file, "r+") as f:
            f.seek(-38, os.SEEK_END)  # Start from the end of the file, -38 is due to min. string's length 38
    
            while f.tell() > 0:
                char = f.read(1)
                if char == "\n":  # Found a line break
                    f.truncate()  # delete the rest of the file
                    break
                f.seek(-1, os.SEEK_CUR)  # Go back 1 bytes

    def block_ip(self, ip, count):
        """Block the specified IP using iptables and log it."""
        print(f"Blocking IP: {ip}")
        try:
            command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(command, check=True)
            print(f"ip blocked: {ip}")
            
            # Save the blocked IP to the file
            with open(self.blocked_ips_file, "a") as file:
                file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked: {ip}\n")
            
            # Logging blocked IP to ddos_logfile.txt
            with open("ddos_logfile.txt", "a") as log_file:
                log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip}, Requests: {count}\n")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to block {ip}: {e}")

    def request_counter(self):
        """Check request counts at regular intervals and block IPs exceeding the limit."""
        while True:
            time.sleep(self.check_interval)
            print("\n[*] Checking traffic...")
            for ip, count in list(self.ip_counter.items()):
                if count > self.request_limit:
                    self.block_ip(ip, count)
                    self.blacklist.append(ip)
                    print(f"[!] IP {ip} blocked - Exceeded request limit: {count}")
            self.ip_counter.clear()  # Reset the request counters

# **Start network sniffing**
ddos = DDoSPreventer()
print("[*] DDoS preventer is running...")

try:
    scapy.sniff(prn=ddos.packet_catch, store=False)
except Exception as e:
    print(f"[ERROR] An error occurred while sniffing: {e}")
