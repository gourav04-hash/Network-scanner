import os
import argparse
import requests
import nmap


def run_nmap_scan(target, scan_all_ports=False):
    """
    Runs an nmap scan on the given target and returns open ports and their services.
    """
    nm = nmap.PortScanner()
    scan_type = "-p 1-65535" if scan_all_ports else "-p 1-1024"
    nm.scan(target, arguments=scan_type)

    services = {}
    try:
        if target in nm.all_hosts():
            host_info = nm[target]
            if 'tcp' in host_info:
                for port in host_info['tcp']:
                    service_name = host_info['tcp'][port].get('name', 'unknown')
                    services[port] = service_name
    except KeyError:
        print(f"[-] Error fetching ports for {target}")
    return services


def discover_subdomains(target):
    """
    Attempts to discover subdomains of the target.
    """
    subdomains = ["www", "mail", "ftp", "dev", "staging", "admin", "test", "m", "api"]
    discovered = []

    for subdomain in subdomains:
        url = f"http://{subdomain}.{target}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                discovered.append(url)
        except requests.RequestException:
            continue
    return discovered


def exploit_detection(target):
    """
    Simulates exploit detection by checking known indicators of vulnerabilities.
    """
    vulnerabilities = []
    try:
        response = requests.get(f"http://{target}", timeout=5)
        server_header = response.headers.get("Server", "Unknown")
        if "Apache" in server_header:
            vulnerabilities.append("Apache detected. Check for known vulnerabilities.")
        if "nginx" in server_header:
            vulnerabilities.append("Nginx detected. Check for known vulnerabilities.")
    except requests.RequestException:
        vulnerabilities.append("Target might not be accessible or vulnerable.")

    return vulnerabilities


def check_default_passwords(target, wordlist=None):
    """
    Checks for default passwords on the target using the provided or default wordlist.
    """
    default_wordlist = ["admin", "password", "123456"]
    wordlist = wordlist or default_wordlist
    found_passwords = []

    for password in wordlist:
        try:
            response = requests.post(f"http://{target}/login", data={'password': password}, timeout=5)
            if response.status_code == 200:
                found_passwords.append(password)
        except requests.RequestException:
            continue

    return found_passwords


def save_results(target, services, vulnerabilities, subdomains):
    """
    Saves scan results to a text file.
    """
    filename = f"{target}_scan_results.txt"
    with open(filename, "w") as file:
        file.write(f"Scan Results for {target}\n")
        file.write("=" * 40 + "\n")
        file.write("\nOpen Ports:\n")
        for port, service in services.items():
            file.write(f"  Port {port}: {service}\n")

        file.write("\nDiscovered Subdomains:\n")
        if subdomains:
            file.write("\n".join(subdomains))
        else:
            file.write("  None found\n")

        file.write("\nPotential Vulnerabilities:\n")
        if vulnerabilities:
            file.write("\n".join(vulnerabilities))
        else:
            file.write("  None detected\n")
    return filename


def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("--targets", nargs="*", help="Target URLs or IPs to scan (space-separated)")
    parser.add_argument("--scan-all-ports", action="store_true", help="Scan all ports (not just common ones)")
    parser.add_argument("--wordlist", type=str, help="Custom wordlist for default password check")
    args = parser.parse_args()

    # Interactive target input if none provided via command-line
    if not args.targets:
        print("No targets provided via command-line.")
        targets_input = input("Enter targets (comma-separated IPs/URLs): ").strip()
        if not targets_input:
            print("No targets provided. Please provide at least one target URL or IP address.")
            return
        targets = [t.strip() for t in targets_input.split(",")]
    else:
        targets = args.targets

    for target in targets:
        print(f"\n[+] Scanning {target}...")
        services = run_nmap_scan(target, scan_all_ports=args.scan_all_ports)
        vulnerabilities = exploit_detection(target)
        subdomains = discover_subdomains(target)

        print("\n[+] Open Ports:")
        for port, service in services.items():
            print(f"  Port {port}: {service}")

        print("\n[+] Discovered Subdomains:")
        if subdomains:
            for sub in subdomains:
                print(f"  {sub}")
        else:
            print("  None")

        print("\n[+] Potential Vulnerabilities:")
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"  {vuln}")
        else:
            print("  None detected.")

        # Save results to file
        saved_file = save_results(target, services, vulnerabilities, subdomains)
        print(f"\n[+] Results saved to {saved_file}")


if __name__ == "__main__":
    main()
