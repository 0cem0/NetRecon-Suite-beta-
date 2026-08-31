import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import sys

import colorama
from colorama import Fore, Style
import requests

colorama.init(autoreset=True)

print(Style.BRIGHT + Fore.MAGENTA + "\n[=== NETWORK RECON SUITE v2.0 ===]\n")

parser = argparse.ArgumentParser(
    description="Network Recon Suite - Network reconnaissance tool"
)
parser.add_argument(
    "-t",
    "--target",
    required=True,
    help="Domain name or IP address (e.g., google.com)",
)
parser.add_argument(
    "-p",
    "--ports",
    default="21,22,80,443,3306,8080",
    help="Comma-separated ports (e.g., 80,443,8000-8005)",
)
parser.add_argument(
    "-T",
    "--threads",
    type=int,
    default=20,
    help="Number of threads (default: 20)",
)
parser.add_argument(
    "-o",
    "--output-dir",
    default="scans",
    help="Output directory (default: scans)",
)

args = parser.parse_args()

print(Fore.GREEN + f"[+] Target selected    : {args.target}")
print(Fore.CYAN + f"[*] Configured ports  : {args.ports}")
print(Fore.CYAN + f"[*] Execution threads : {args.threads}")
print(Fore.BLUE + f"[*] Output directory  : {args.output_dir}\n")


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        print(Fore.GREEN + f"[+] Resolved IP: {ip}")
    except socket.gaierror:
        print(
            Fore.RED
            + f"[-] Error: Unable to resolve target '{target}'"
        )
        sys.exit(1)

    try:
        host = socket.gethostbyaddr(ip)[0]
        print(Fore.CYAN + f"[*] Reverse DNS: {host}")
    except (socket.herror, socket.gaierror):
        host = "Unknown"
        print(Fore.YELLOW + "[!] Reverse DNS: No record found")

    return ip, host


def get_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,mobile,proxy,hosting"
        res = requests.get(url, timeout=5)
        data = res.json()
        if data.get("status") == "success":
            print(
                Fore.GREEN
                + f"[+] Geolocation: {data.get('city')}, {data.get('country')}"
            )
            print(Fore.CYAN + f"[*] ISP: {data.get('isp')}")
            return data
        else:
            print(Fore.YELLOW + "[-] Geolocation not available.")
            return {}
    except Exception as e:
        print(Fore.RED + f"[-] Geolocation API Error: {e}")
        return {}


def parse_ports(port_string):
    port_list = []
    ports = port_string.split(",")

    for port in ports:
        port = port.strip()
        try:
            if "-" in port:
                start, end = port.split("-")
                for p in range(int(start), int(end) + 1):
                    port_list.append(p)
            else:
                port_list.append(int(port))
        except ValueError:
            continue

    return sorted(list(set(port_list)))


def analyze_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip, port))

        if result == 0:
            print(Fore.GREEN + f"  [+] Port {port} is open!")

            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                response = s.recv(1024)
                banner = (
                    response.decode("utf-8", errors="ignore")
                    .strip()
                    .split("\n")[0]
                )
            except Exception:
                banner = "No banner"

            s.close()
            return {"port": port, "state": "OPEN", "banner": banner}

        s.close;
    except Exception:
        pass

    return None


def scan_ports(ip, port_list, max_threads):
    print(
        Fore.YELLOW
        + f"[*] Starting scan on {len(port_list)} ports ({max_threads} threads)..."
    )
    open_ports_list = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(analyze_port, ip, port) for port in port_list
        ]

        for future in futures:
            res = future.result()
            if res:
                open_ports_list.append(res)

    return open_ports_list


# Execution
target_ip, target_host = resolve_target(args.target)
geo_data = get_geolocation(target_ip)
ports_to_scan = parse_ports(args.ports)
ports_found = scan_ports(target_ip, ports_to_scan, args.threads)

report = {
    "target": args.target,
    "ip": target_ip,
    "host_name": target_host,
    "geolocation": geo_data,
    "open_ports": ports_found,
}

output_folder = Path(args.output_dir)
output_folder.mkdir(parents=True, exist_ok=True)

clean_filename = args.target.replace("/", "_").replace(":", "_")
file_path = output_folder / f"recon_{clean_filename}.json"

with open(file_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4, ensure_ascii=False)

print(
    Fore.GREEN
    + f"\n[+] Scan completed! Report saved in: {file_path}"
)
