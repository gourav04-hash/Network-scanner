
# Network Vulnerability Scanner

This is a simple **Network Vulnerability Scanner** built in Python, designed to identify potential security risks in target systems. The scanner performs multiple checks on the target(s), including:

- **Port scanning** using `nmap`
- **Subdomain discovery** through common subdomains
- **Exploit detection** based on known server signatures
- **Default password check** using a pre-configured wordlist

## Features
- **Nmap Port Scanning:** Scans open ports and identifies services running on those ports (supports scanning all ports or just common ones).
- **Subdomain Discovery:** Attempts to discover subdomains of the target to identify potential entry points.
- **Exploit Detection:** Checks for vulnerable server types based on HTTP headers (e.g., Apache, Nginx).
- **Default Password Check:** Attempts to log in to the target using a list of default passwords.
- **Result Saving:** Saves the results of the scan (open ports, discovered subdomains, and vulnerabilities) to a text file.

## Requirements
- Python 3.x
- `requests` library: To make HTTP requests
- `nmap` library: To perform network scanning (requires `nmap` installed on your system)

You can install the required libraries using pip:

```
pip install requests python-nmap
```

Additionally, you must have the `nmap` tool installed on your system. You can install it via:

- **Ubuntu/Debian:** `sudo apt install nmap`
- **MacOS:** `brew install nmap`
- **Windows:** Download from [nmap.org](https://nmap.org/download.html)

## Usage

### Command Line Interface (CLI)
To run the scanner, use the following command structure:

```
python scanner.py --targets <target1> <target2> ... [--scan-all-ports] [--wordlist <custom_wordlist>]
```

- `--targets`: A space-separated list of IPs or URLs you want to scan (e.g., `--targets 192.168.1.1 example.com`).
- `--scan-all-ports`: Flag to scan all ports (1-65535) instead of just common ports (1-1024).
- `--wordlist`: Optionally provide a custom wordlist to check for default passwords.

#### Example 1: Scan specific targets with common ports
```
python scanner.py --targets 192.168.1.1 example.com
```

#### Example 2: Scan all ports on a target
```
python scanner.py --targets 192.168.1.1 --scan-all-ports
```

#### Example 3: Use a custom wordlist for default password checks
```
python scanner.py --targets example.com --wordlist custom_wordlist.txt
```

### Interactive Mode
If no targets are specified via the command-line, the script will prompt you to input target IPs or URLs interactively.

### Scan Results
The results of the scan will be saved in a text file named `<target>_scan_results.txt`. This file includes:

- Open ports and services
- Discovered subdomains
- Potential vulnerabilities (e.g., Apache or Nginx servers detected)

## Sample Output

```
[+] Scanning 192.168.1.1...
[+] Open Ports:
  Port 80: http
  Port 443: https

[+] Discovered Subdomains:
  www.example.com
  mail.example.com

[+] Potential Vulnerabilities:
  Apache detected. Check for known vulnerabilities.

[+] Results saved to 192.168.1.1_scan_results.txt
```

## Contributing
Feel free to fork this repository, submit issues, and contribute improvements. Pull requests are welcome!

## License
This project is licensed under the MIT License.
