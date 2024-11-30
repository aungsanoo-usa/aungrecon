# AungRecon

![AungRecon](https://img.shields.io/badge/AungRecon-V1.0-green)

AungRecon is a comprehensive, automated reconnaissance script for web application security assessments. It performs multiple security checks and scans on a target domain, including subdomain enumeration, SQL injection, XSS, open redirects, LFI vulnerabilities, and more. The tool integrates several popular security tools, streamlining the workflow of security analysts and penetration testers.

## Features

- **WhatWeb Scan**: Identifies technologies, plugins, and versions used by the target website.
- **Subdomain Enumeration**: Discovers and filters alive subdomains.
- **Subdomain Takeover Detection**: Identifies possible subdomain takeovers.
- **SQL Injection Detection**: Searches for SQLi vulnerabilities using parameterized URLs.
- **Cross-Site Scripting (XSS) Detection**: Scans for XSS vulnerabilities.
- **Open Redirect Detection**: Finds possible open redirect vulnerabilities.
- **Local File Inclusion (LFI) Detection**: Identifies possible LFI vulnerabilities.
- **Nuclei Vulnerability Scans**: Executes multiple vulnerability templates via Nuclei.

## Prerequisites

Before you can use **AungRecon**, ensure you have the following tools installed on your system:

- `subfinder`
- `paramspider`
- `whatweb`
- `uro`
- `httpx`
- `subzy`
- `bsqli`
- `urldedupe`
- `anew`
- `Gxss`
- `kxss`
- `ffuf`
- `gau`
- `gf`
- `nuclei`
- `Dalfox`
- `katana`
- `nikto`
- `SecretFinder`

These tools are required for full functionality. You can install them manually or automate the process by using the provided `install.sh` script .

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aungsanoo-usa/aungrecon.git
   cd aungrecon
   ```
   ```bash
   chmod +x install.sh
   chmod +x aungrecon.sh
   

 2. Usage:
   To run AungRecon on a target domain, simply execute the script with the following command:

   ```bash
    ./install.sh
   ```
   ```bash
    ./aungrecon.sh
   ```


 ## Output
 The results of the scan will be saved in the output directory, including:

- **xss_vul.txt**:: XSS vulnerabilities.
- **open_redirect_vul.txt**:: Open redirect vulnerabilities.
- **lfi_vul.txt**:: LFI vulnerabilities.
- **bsqli_results**:: SQLi vulnerabilities.
- **whatweb.txt**:: Information from the WhatWeb scan.
- **multiple_vulnerabilities.txt**:: Results from Nuclei scans.

<div align="center">
   <a href="https://github.com/aungsanoo-usa/aungrecon"><img src="https://github.com/aungsanoo-usa/aungrecon/blob/main/images.png?raw=true"  align="center"/></a>
</div>
  
## Contributing
If you'd like to contribute to AungRecon, feel free to fork the repository and submit a pull request. Issues and feature requests are also welcome!

## Disclaimer
This script is designed for educational purposes only. The author is not responsible for any misuse of this tool. Please ensure you have permission from the domain owner before running the scans.

