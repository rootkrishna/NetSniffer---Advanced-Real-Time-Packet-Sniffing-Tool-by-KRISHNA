from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{timestamp}] [TCP] {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{timestamp}] [UDP] {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        else:
            print(f"[{timestamp}] [IP] {ip_src} -> {ip_dst} [Proto: {proto}]")

def banner():
    print(r"""
 _   _      _   _       _  __        __         
| \ | | ___| |_| |__   | | \ \      / /__  _ __ 
|  \| |/ _ \ __| '_ \  | |  \ \ /\ / / _ \| '__|
| |\  |  __/ |_| | | | | |___\ V  V / (_) | |   
|_| \_|\___|\__|_| |_| |_____\_/\_/ \___/|_|   
         🛰️ NetSniffer by KRISHNA ⚔️
    """)

def main():
    banner()
    print("[*] Starting packet sniffing... Press Ctrl+C to stop.\n")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
