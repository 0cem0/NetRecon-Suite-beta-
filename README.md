> 🇫🇷 *Pour la version française du README, cliquez [ici](README.fr.md).*

# NetRecon Suite (beta)

> A lightweight, fast, and multithreaded Python tool for network reconnaissance and target analysis.

`NetRecon Suite` allows you to quickly gather information on a domain name or IP address: DNS resolution, reverse DNS, geographical/ISP geolocation, customizable port scanning (including ranges), and service banner grabbing. Results are automatically saved in JSON format.

---

## Features

- **DNS & Reverse DNS Resolution**: Domain to IP conversion and associated hostname lookup.
- **IP Geolocation**: Country, city, and ISP retrieval via the *ip-api* API.
- **Advanced Port Parsing**: Support for individual port lists (`80,443`) and ranges (`8000-8005`).
- **Multithreaded TCP Scan**: Accelerated parallel execution with `concurrent.futures`.
- **Banner Grabbing**: Automatic capture of HTTP / service banners on open ports.
- **JSON Report**: Automatic structured export to a destination folder.
- **Colorized CLI Interface**: Clear terminal display powered by `colorama`.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/0cem0/netrecon-suite-beta-.git](https://github.com/0cem0/netrecon-suite-beta-.git)
   cd netrecon-suite-beta-
   ```

2. **Install dependencies**:
   ```bash
   pip install colorama requests
   ```

---

## Usage

```bash
python main.py -t <TARGET> [OPTIONS]
```

### Available Options

| Option | Long option | Description | Default value |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target domain name or IP address *(Required)* | *None* |
| `-p` | `--ports` | List or range(s) of ports to scan | `21,22,80,443,3306,8080` |
| `-T` | `--threads` | Number of threads for parallel scanning | `20` |
| `-o` | `--output-dir` | Output directory for the JSON report | `scans` |

---

## Examples

**Basic scan:**
```bash
python main.py -t scanme.nmap.org
```

**Extended scan with port range and increased threads:**
```bash
python main.py -t 192.168.1.1 -p 22,80,443,8000-8010 -T 50 -o my_scans
```

---

## JSON Report Structure

Each scan generates a `recon_<target>.json` file structured as follows:

```json
{
    "cible": "scanme.nmap.org",
    "ip": "45.33.32.156",
    "host_name": "scanme.nmap.org",
    "geolocalisation": {
        "status": "success",
        "country": "United States",
        "city": "Fremont",
        "isp": "Linode"
    },
    "ports_ouverts": [
        {
            "port": 22,
            "state": "OPEN",
            "banner": "SSH-2.0-OpenSSH_7.4p1"
        },
        {
            "port": 80,
            "state": "OPEN",
            "banner": "HTTP/1.1 200 OK"
        }
    ]
}
```

---

## ⚠️ Legal Disclaimer

This tool is intended **strictly for educational purposes** and authorized security testing. Scanning targets without prior authorization is illegal.
