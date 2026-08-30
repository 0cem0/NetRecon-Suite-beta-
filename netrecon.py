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
    description="Network Recon Suite - Outil de reconnaissance réseau"
)
parser.add_argument(
    "-t",
    "--target",
    required=True,
    help="Nom de domaine ou adresse IP (ex: google.com)",
)
parser.add_argument(
    "-p",
    "--ports",
    default="21,22,80,443,3306,8080",
    help="Ports séparés par des virgules (ex: 80,443,8000-8005)",
)
parser.add_argument(
    "-T",
    "--threads",
    type=int,
    default=20,
    help="Nombre de threads (défaut: 20)",
)
parser.add_argument(
    "-o",
    "--output-dir",
    default="scans",
    help="Dossier de sauvegarde (défaut: scans)",
)

args = parser.parse_args()

print(Fore.GREEN + f"[+] Cible sélectionnée  : {args.target}")
print(Fore.CYAN + f"[*] Ports paramétrés    : {args.ports}")
print(Fore.CYAN + f"[*] Threads d'exécution : {args.threads}")
print(Fore.BLUE + f"[*] Dossier de sortie   : {args.output_dir}\n")


def solve_target(target):
    try:
        ip = socket.gethostbyname(target)
        print(Fore.GREEN + f"[+] IP résolue : {ip}")
    except socket.gaierror:
        print(
            Fore.RED
            + f"[-] Erreur : Impossible de résoudre la cible '{target}'"
        )
        sys.exit(1)

    try:
        host = socket.gethostbyaddr(ip)[0]
        print(Fore.CYAN + f"[*] Reverse DNS : {host}")
    except (socket.herror, socket.gaierror):
        host = "Inconnu"
        print(Fore.YELLOW + "[!] Reverse DNS : Aucun enregistrement trouvé")

    return ip, host


def get_localisation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,mobile,proxy,hosting"
        res = requests.get(url, timeout=5)
        data = res.json()
        if data.get("status") == "success":
            print(
                Fore.GREEN
                + f"[+] Géolocalisation : {data.get('city')}, {data.get('country')}"
            )
            print(Fore.CYAN + f"[*] FAI / ISP       : {data.get('isp')}")
            return data
        else:
            print(Fore.YELLOW + "[-] Géolocalisation non disponible.")
            return {}
    except Exception as e:
        print(Fore.RED + f"[-] Erreur API Géolocalisation : {e}")
        return {}


def parser_ports(chaine_ports):
    liste = []
    ports = chaine_ports.split(",")

    for port in ports:
        port = port.strip()
        try:
            if "-" in port:
                debut, fin = port.split("-")
                for p in range(int(debut), int(fin) + 1):
                    liste.append(p)
            else:
                liste.append(int(port))
        except ValueError:
            continue

    return sorted(list(set(liste)))


def analyser_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip, port))

        if result == 0:
            print(Fore.GREEN + f"  [+] Le port {port} est ouvert !")

            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                reponse = s.recv(1024)
                banner = (
                    reponse.decode("utf-8", errors="ignore")
                    .strip()
                    .split("\n")[0]
                )
            except Exception:
                banner = "Pas de bannière"

            s.close()
            return {"port": port, "state": "OPEN", "banner": banner}

        s.close()
    except Exception:
        pass

    return None


def scan_ports(ip, liste_ports, max_threads):
    print(
        Fore.YELLOW
        + f"[*] Lancement du scan sur {len(liste_ports)} ports ({max_threads} threads)..."
    )
    liste_ports_ouverts = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(analyser_port, ip, port) for port in liste_ports
        ]

        for future in futures:
            res = future.result()
            if res:
                liste_ports_ouverts.append(res)

    return liste_ports_ouverts


#Execution
ip_cible, host_cible = solve_target(args.target)
data_geo = get_localisation(ip_cible)
ports_a_scanner = parser_ports(args.ports)
ports_found = scan_ports(ip_cible, ports_a_scanner, args.threads)

rapport = {
    "cible": args.target,
    "ip": ip_cible,
    "host_name": host_cible,
    "geolocalisation": data_geo,
    "ports_ouverts": ports_found,
}

dossier_sortant = Path(args.output_dir)
dossier_sortant.mkdir(parents=True, exist_ok=True)

nom_fichier_propre = args.target.replace("/", "_").replace(":", "_")
chemin_fichier = dossier_sortant / f"recon_{nom_fichier_propre}.json"

with open(chemin_fichier, "w", encoding="utf-8") as f:
    json.dump(rapport, f, indent=4, ensure_ascii=False)

print(
    Fore.GREEN
    + f"\n[+] Scan terminé ! Rapport sauvegardé dans : {chemin_fichier}"
)
