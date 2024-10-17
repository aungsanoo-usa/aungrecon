#!/bin/bash

# ANSI color code variables
declare -A colors=(
    [red]="\e[0;91m"
    [blue]="\e[0;94m"
    [yellow]="\e[0;33m"
    [green]="\e[0;92m"
    [cyan]="\e[0;36m"
    [uline]="\e[0;35m"
    [reset]="\e[0m"
)

output_dir="$HOME/aungrecon/output"
tools=("subfinder" "paramspider" "whatweb" "uro" "httpx" "subzy" "urldedupe" "anew" "openredirex" "ffuf" "gau" "gf" "nuclei")

# Print logo
echo -e "${colors[yellow]}Welcome to Aung Recon main script"
cat << "EOF"
#              ╭━━━╮╱╱╱╱╱╱╱╱╱╭━━━╮
#              ┃╭━╮┃╱╱╱╱╱╱╱╱╱┃╭━╮┃
#              ┃┃╱┃┣╮╭┳━╮╭━━╮┃╰━╯┣━━┳━━┳━━┳━╮
#              ┃╰━╯┃┃┃┃╭╮┫╭╮┃┃╭╮╭┫┃━┫╭━┫╭╮┃╭╮╮
#              ┃╭━╮┃╰╯┃┃┃┃╰╯┃┃┃┃╰┫┃━┫╰━┫╰╯┃┃┃┃
#              ╰╯╱╰┻━━┻╯╰┻━╮┃╰╯╰━┻━━┻━━┻━━┻╯╰╯
#              ╱╱╱╱╱╱╱╱╱╱╭━╯┃
#              ╱╱╱╱╱╱╱╱╱╱╰━━╯  aungsanoo.com
EOF
echo -e "${colors[reset]}"

# Tool check function
check_tools() {
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${colors[red]}[+] $tool is not installed. Please run install.sh or install it manually.${colors[reset]}"
            exit 1
        fi
    done
}

# Prepare and clean output files before each scan
prepare_output_files() {
    echo -e "${colors[blue]}[+] Preparing and cleaning output files...${colors[reset]}"
    mkdir -p "$output_dir"
    for file in xss_vul.txt open_redirect_vul.txt lfi_vul.txt bsqli_vulnerable_urls.txt multiple_vulnerabilities.txt final.txt whatweb.txt; do
        > "$output_dir/$file"  # Truncate (empty) the files
    done
}

# WhatWeb scan to gather website information
run_whatweb_scan() {
    echo -e "${colors[yellow]}[+] Running WhatWeb scan to gather website information...${colors[reset]}"
    whatweb -a 3 "$website_url" | tee "$output_dir/whatweb.txt"
}

# Subdomain discovery and filtering
find_subdomains() {
    echo -e "${colors[yellow]}[+] Finding subdomains...${colors[reset]}"
    subfinder -d "$website_input" -all -recursive > "sub.txt"
    echo -e "${colors[yellow]}[+] Filtering alive subdomains...${colors[reset]}"
    cat "sub.txt" | httpx -silent > "alivesub.txt"
}

# Subdomain takeover detection
check_subdomain_takeover() {
    echo -e "${colors[yellow]}[+] Checking for subdomain takeover...${colors[reset]}"
    subzy run --targets "sub.txt"
}

# SQLi detection
find_sqli_vulnerabilities() {
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities...${colors[reset]}"
    paramspider -l alivesub.txt
    cd results
    cat *.txt | sed 's/=.*/=/' > "$output_dir/final.txt"
    
    # Check if final.txt exists and has content (parameterized URLs)
    if [[ -f "$output_dir/final.txt" && -s "$output_dir/final.txt" ]]; then
        echo -e "${colors[blue]}[+] Parameters found, proceeding with SQLi scan.${colors[reset]}"
        cd "$HOME/aungrecon/sqli-scanner"
        python3 scanner.py -u "$output_dir/final.txt" -p payloads_sqli.txt -b payloads_blind_sqli.txt -o bsqli_vulnerable_urls.txt
        cp bsqli_vulnerable_urls.txt "$output_dir/bsqli_vulnerable_urls.txt"
    else
        echo -e "${colors[red]}[!] No parameterized endpoints found in final.txt. Skipping SQLi scanning.${colors[reset]}"
    fi
}

# Main vulnerabilities scan (Nuclei)
run_nuclei_scan() {
    echo -e "${colors[yellow]}[+] Running Nuclei for multiple vulnerabilities...${colors[reset]}"
    nuclei -l "alivesub.txt" -t "$HOME/aungrecon/priv8-Nuclei" -severity low,medium,high,critical -o "$output_dir/multiple_vulnerabilities.txt"
}

# Other vulnerability tests (XSS, Open Redirect, LFI)
run_vulnerability_tests() {
    echo -e "${colors[yellow]}[+] Finding XSS vulnerabilities...${colors[reset]}"
    python3 "$HOME/aungrecon/xss_vibes/main.py" -f "$output_dir/final.txt" -t 7 -o "$output_dir/xss_vul.txt"
    echo -e "${colors[yellow]}[+] Testing for Open Redirect vulnerabilities...${colors[reset]}"
    cat "$HOME/aungrecon/results/allurls.txt" | openredirex -p "$HOME/aungrecon/or.txt" -k "FUZZ" -c 30 > "$output_dir/open_redirect_vul.txt"
    echo -e "${colors[yellow]}[+] Testing for LFI vulnerabilities...${colors[reset]}"
    gau "$website_input" | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | ffuf -u {} -w lfi.txt -c -mr "root:x:0:" -v > "$output_dir/lfi_vul.txt"
}

# Cleanup intermediate files
cleanup_files() {
    echo -e "${colors[yellow]}[+] Cleaning up intermediate files...${colors[reset]}"
    rm -f sub.txt alivesub.txt allurls.txt
}

# Final output message
output_summary() {
    echo -e "${colors[green]}Filtered URLs have been saved to the respective output files in the 'output' directory:${colors[reset]}"
    echo -e "${colors[cyan]}- XSS: $output_dir/xss_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- Open Redirect: $output_dir/open_redirect_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- LFI: $output_dir/lfi_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- SQLi: $output_dir/bsqli_vulnerable_urls.txt${colors[reset]}"
    echo -e "${colors[cyan]}- Multiple vulnerabilities: $output_dir/multiple_vulnerabilities.txt${colors[reset]}"
}

# Main script execution flow
check_tools
read -p "[+] Enter the website domain: " website_input
website_url="${website_input#http://}"
website_url="${website_input#https://}"
website_url="https://$website_url"

prepare_output_files  # Clean and overwrite files each scan
run_whatweb_scan      # Run WhatWeb scan first
find_subdomains
check_subdomain_takeover
find_sqli_vulnerabilities  # Check if final.txt exists and is not empty before SQLi scan
run_nuclei_scan
run_vulnerability_tests
cleanup_files
output_summary
