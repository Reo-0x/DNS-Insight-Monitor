from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP, UDP, TCP
import sys
import platform
import logging

# List of known secure DNS server IPs (DoT/DoH)
SECURE_DNS_SERVERS = [
    "1.1.1.1",       # Cloudflare
    "8.8.8.8",       # Google
    "9.9.9.9",       # Quad9
    "208.67.222.222", # OpenDNS
]


def print_banner():
    print(f"{'made by Reo-0x':^50}")
    print("\n" + "="*50)
    print(f"{'DNS Insight Monitor':^50}")
    print("="*50)
    print(f"{'IP Address':<15} | {'DNS Query':<25} | {'Status':<15}")
    print("-"*50)

def is_secure(packet, dns_query):
    """Check if the query is for a secure DNS server/"""
    dst_ip = packet[IP].dst
    return (
        dst_ip in SECURE_DNS_SERVERS 
    )

def process_packet(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            # Check for DNS over UDP port 53
            if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNSQR):
                dns_query = packet[DNSQR].qname.decode('utf-8', 'ignore').rstrip('.')
                if is_secure(packet, dns_query):
                    print(f"{src_ip:<15} | {dns_query:<25} | {'SECURE (DoT/DoH)':<15}")
                else:
                    print(f"{src_ip:<15} | {dns_query:<25} | {'INSECURE':<15}")
            # Check for DNS-over-TLS (DoT) over TCP port 853
            elif packet.haslayer(TCP) and packet[TCP].dport == 853:
                print(f"{src_ip:<15} | {'[Encrypted DoT]':<25} | {'SECURE (DoT)':<15}")
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")

def main():
    try:
        print_banner()
        sniff(filter="udp port 53 or tcp port 853", prn=process_packet, store=0)
        
    except PermissionError:
        os_type = platform.system().lower()
        if os_type == 'linux' or os_type == 'darwin':
            print("\n\033[91mERROR: Permission denied. Please run with sudo:\033[0m")
            print(f"\033[93msudo python3 {sys.argv[0]}\033[0m\n")
        else:
            print("\n\033[91mERROR: Please run as Administrator\033[0m\n")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n\033[93m[!] Monitoring stopped by user. Exiting...\033[0m")
        sys.exit(0)
        
    except ImportError:
        print("\n\033[91mERROR: Required packages not installed. Install with:")
        print("\033[93mpip install scapy\033[0m\n")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n\033[91mCRITICAL ERROR: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()