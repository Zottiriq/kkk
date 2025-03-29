import scapy.all as scapy
from collections import defaultdict
import time
import threading
import os
import subprocess

class ddos_preventer:
    def __init__(self):
        self.request_limit = 100
        self.check_interval = 10
        self.ip_counter = defaultdict(int)
    
    def packet_catch(self, packet):
        if packet.haslayer(IP):
            ip_source = packet[IP].src
            self.ip_counter[ip_source] += 1
    
    def block_ip(ip):
        print(f"ip: {ip} is blocking")

        try:
            command = (["iptables", "-A", "INPUT", "-s", ip "-j", "DROP"], check=True)
            subprocess.run(command)
        except subprocess.CalledProcessError as a:
            print(f"[ERROR] failed to block {ip}: {e}")


    def request_counter(self):
        while True:
            time.sleep(self.check_interval)
            print("\nChecking traffic...")
            for ip, count in list(self.ip_counter.items()):
                if count > self.request_limit:
                    block_ip(ip)
                    print(f"ip: {ip} has been blocked\ndue to request limit reached {count}")
            self.ip_counter.clear()
        