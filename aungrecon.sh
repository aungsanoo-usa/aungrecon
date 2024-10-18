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
tools=("subfinder" "paramspider" "whatweb" "uro" "httpx" "subzy" "urldedupe" "anew" "openredirex" "ffuf" "gau" "gf" "nuclei" "dalfox")

# Print logo
echo -e "${colors[yellow]}##########################################################"
echo -e "##### Welcome to the AungRecon main script #####"
echo -e "##########################################################${colors[reset]}"
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
    subfinder -d "$website_input" -all -recursive > "$output_dir/subdomains.txt"
    echo -e "${colors[yellow]}[+] Filtering alive subdomains...${colors[reset]}"
    cat "$output_dir/subdomains.txt" | httpx -silent > "$output_dir/alivesub.txt"
}

# Subdomain takeover detection
check_subdomain_takeover() {
    echo -e "${colors[yellow]}[+] Checking for subdomain takeover...${colors[reset]}"
    subzy run --targets "$output_dir/subdomains.txt"
}

# SQLi detection using SQLMap for detection only (no attack)
find_sqli_vulnerabilities() {
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities (detection only, no attack)...${colors[reset]}"
    paramspider -l "$output_dir/alivesub.txt"
    cd results
    cat *.txt > allurls.txt
    cat allurls.txt | sed 's/=.*/=/' > "$output_dir/final.txt"
    
    # Check if final.txt exists and has content (parameterized URLs)
    if [[ -f "$output_dir/final.txt" && -s "$output_dir/final.txt" ]]; then
        echo -e "${colors[blue]}[+] Parameters found, proceeding with SQLMap detection scan.${colors[reset]}"
        
        # Loop through each URL in final.txt and run SQLMap for detection only
        while IFS= read -r url; do
            echo -e "${colors[blue]}[+] Testing $url with SQLMap (detection only)...${colors[reset]}"
            
            # SQLMap command for detection only (no attack)
            sqlmap -u "$url" --batch --smart --level=1 --risk=1 --technique=BEU --output-dir="$output_dir/sqlmap_results"
            
        done < "$output_dir/final.txt"
        
        echo -e "${colors[green]}[+] SQLMap detection scan completed. Results saved in the output directory.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No parameterized endpoints found in final.txt. Skipping SQLi detection scan.${colors[reset]}"
    fi
}

# LFI detection for all subdomains using ffuf
run_lfi_scan() {
    echo -e "${colors[yellow]}[+] Testing for LFI vulnerabilities on all subdomains using ffuf...${colors[reset]}"
    
    # LFI payload file path
    lfi_payloads="$HOME/aungrecon/lfi.txt"
    
    if [[ -f "$lfi_payloads" ]]; then
        # Use ffuf to scan all alive subdomains for LFI vulnerabilities
        while IFS= read -r url; do
            echo -e "${colors[blue]}[+] Testing $url for LFI vulnerabilities...${colors[reset]}"
            gau "$url" | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | ffuf -u {} -w "$lfi_payloads" -c -mr "root:x:0:" -o "$output_dir/lfi_vul.txt"
        done < "$output_dir/alivesub.txt"
        
        echo -e "${colors[green]}[+] LFI scan completed for all subdomains. Results saved in lfi_vul.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] LFI payload file not found. Skipping LFI scan.${colors[reset]}"
    fi
}

# Open Redirect detection using OpenRedireX
run_open_redirect_scan() {
    echo -e "${colors[yellow]}[+] Testing for Open Redirect vulnerabilities using OpenRedireX...${colors[reset]}"
    
    gau "$website_input" | gf redirect | uro | sed 's/=.*/=/' | openredirex -p "$HOME/aungrecon/or.txt" -k "FUZZ" -c 30 > "$output_dir/open_redirect_vul.txt"
    
    echo -e "${colors[green]}[+] Open Redirect scan completed. Results saved in open_redirect_vul.txt.${colors[reset]}"
}

# XSS detection with DalFox using custom payloads
run_xss_scan() {
    echo -e "${colors[yellow]}[+] Finding XSS vulnerabilities using DalFox with custom payloads...${colors[reset]}"
    
    # Path to the custom payload file
    payload_file="$HOME/aungrecon/xss.txt"
    
    # Use DalFox to scan URLs for XSS vulnerabilities with custom payloads
    if [[ -f "$payload_file" ]]; then
        while IFS= read -r url; do
            echo -e "${colors[blue]}[+] Testing $url for XSS with DalFox and custom payloads...${colors[reset]}"
            
            # DalFox scan for XSS using custom payloads
            dalfox file "$output_dir/final.txt" --silence --p "$payload_file" --output "$output_dir/xss_vul.txt"
            
        done < "$output_dir/final.txt"
        
        echo -e "${colors[green]}[+] DalFox XSS scan completed with custom payloads. Results saved in xss_vul.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] Custom payload file not found. Skipping XSS scan.${colors[reset]}"
    fi
}

# Cleanup intermediate files
cleanup_files() {
    echo -e "${colors[yellow]}[+] Cleaning up intermediate files...${colors[reset]}"
    rm -f "$output_dir/subdomains.txt" "$output_dir/alivesub.txt" "$output_dir/allurls.txt"
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
find_sqli_vulnerabilities  # SQLMap scan for detection only (no attack)
run_lfi_scan           # LFI scan using ffuf
run_open_redirect_scan # Open Redirect scan using OpenRedireX
run_xss_scan           # XSS detection with DalFox and custom payloads
cleanup_files
output_summary
