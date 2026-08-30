# NetRecon Suite (beta)

> Un outil léger, rapide et multithreadé en Python pour la reconnaissance réseau et l'analyse de cibles.

`NetRecon Suite` permet de collecter rapidement des informations sur un nom de domaine ou une adresse IP : résolution DNS, reverse DNS, géolocalisation géographique/ISP, scan de ports personnalisable (plages incluses) et récupération des bannières de services. Les résultats sont sauvegardés automatiquement sous format JSON.

---

## Fonctionnalités

- **Résolution DNS & Reverse DNS** : Conversion domaine -> IP et recherche du nom d'hôte associé.
- **Géolocalisation d'IP** : Récupération du pays, de la ville et du FAI (ISP) via l'API *ip-api*.
- **Parsing avancé de ports** : Support des listes individuelles (`80,443`) et des plages de ports (`8000-8005`).
- **Scan TCP Multithreadé** : Exécution parallèle accélérée avec `concurrent.futures`.
- **Banner Grabbing** : Capture automatique des bannières HTTP / services sur les ports ouverts.
- **Rapport JSON** : Exportation structurée automatique dans un dossier de destination.
- **Interface CLI Colorée** : Affichage clair en terminal grâce à `colorama`.

---

## Installation

1. **Cloner le projet** :
   ```bash
   git clone https://github.com/0cem0/netrecon-suite-beta-.git
   cd netrecon-suite-beta-
   ```

2. **Installer les dépendances** :
   ```bash
   pip install colorama requests
   ```

---

## Utilisation

```bash
python main.py -t <CIBLE> [OPTIONS]
```

### Options disponibles

| Option | Format long | Description | Valeur par défaut |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Nom de domaine ou adresse IP cible *(Obligatoire)* | *Aucune* |
| `-p` | `--ports` | Liste ou plage(s) de ports à scanner | `21,22,80,443,3306,8080` |
| `-T` | `--threads` | Nombre de threads pour le scan parallèle | `20` |
| `-o` | `--output-dir` | Dossier d'enregistrement du rapport JSON | `scans` |

---

## Exemples

**Scan de base :**
```bash
python main.py -t scanme.nmap.org
```

**Scan étendu avec plage de ports et threads augmentés :**
```bash
python main.py -t 192.168.1.1 -p 22,80,443,8000-8010 -T 50 -o mes_scans
```

---

## Structure du Rapport JSON

Chaque scan génère un fichier `recon_<cible>.json` structuré comme suit :

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

## ⚠️ Avertissement Légal

Cet outil est destiné **exclusivement à des fins éducatives** et de tests de sécurité autorisés. L'analyse de cibles sans autorisation préalable est illégale.
