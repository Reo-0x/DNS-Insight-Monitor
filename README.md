# DNS Insight Monitor

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A real-time DNS traffic analyzer that identifies secure (DoT/DoH) and insecure DNS queries on your network.

## Features

- 🛡️ **Detect Insecure DNS**: Identify DNS queries sent over unencrypted UDP port 53
- 🔒 **Recognize Secure DNS**: Flag queries to known DoT/DoH providers (Cloudflare, Google, Quad9, OpenDNS)
- 🌐 **Traffic Monitoring**: Real-time analysis of network traffic
- 📋 **Clear Output**: Tabular display showing source IPs, queried domains, and security status

## Prerequisites

- Python 3.x
- `scapy` library
- Root/Administrator privileges (for packet capture)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/dns-insight-monitor.git
   cd dns-insight-monitor
   ```

2. Install dependencies:
   ```bash
   pip install scapy
   ```

## Usage

Run with elevated privileges:
```bash
sudo python3 dns_insight.py
```

Sample output:
```
                   made by Reo-0x                    
====================================================
               DNS Insight Monitor                  
====================================================
IP Address      | DNS Query               | Status     
----------------------------------------------------
192.168.1.12    | example.com             | INSECURE   
192.168.1.45    | [Encrypted DoT]         | SECURE (DoT)
192.168.1.102   | cloudflare-dns.com      | SECURE (DoT/DoH)
```

## How It Works

- **Secure DNS Detection**:
  - Recognizes DNS-over-TLS (DoT) on TCP port 853
  - Checks against predefined secure DNS server IPs:
    ```python
    SECURE_DNS_SERVERS = [
        "1.1.1.1",        # Cloudflare
        "8.8.8.8",        # Google
        "9.9.9.9",        # Quad9
        "208.67.222.222", # OpenDNS
    ]
    ```
- **Insecure DNS Detection**:
  - Flags all UDP/53 traffic not going to known secure servers

## Customization

Edit the `SECURE_DNS_SERVERS` list in the script to add/remove DNS providers:
```python
SECURE_DNS_SERVERS = [
    "1.1.1.1",        # Cloudflare
    "8.8.8.8",        # Google
    # Add more trusted servers here
]
```

## Troubleshooting

- **Permission Denied?**
  ```bash
  sudo python3 dns_insight.py
  ```
  
- **Missing Dependencies?**
  ```bash
  pip install scapy
  ```

## Contributing

Contributions welcome! Open an issue or PR for:
- New DNS providers
- Additional detection methods
- UI improvements
- Bug fixes

## License

MIT License - see [LICENSE](LICENSE) file

---

**Disclaimer**: Use this tool only on networks you own or have permission to monitor. Respect privacy and comply with local laws.
