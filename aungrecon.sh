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
tools=("subfinder" "paramspider" "whatweb" "uro" "httpx" "subzy" "urldedupe" "anew" "ffuf" "gau" "gf" "nuclei" "dalfox" "katana")

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
    for file in xss_vul.txt open_redirect_vul.txt lfi_vul.txt multiple_vulnerabilities.txt subdomains.txt alivesub.txt final.txt whatweb.txt katana_endpoints.txt subzy_results.txt; do
        > "$output_dir/$file"  # Truncate (empty) the files
    done
}

# WhatWeb scan to gather website information
run_whatweb_scan() {
    echo -e "${colors[yellow]}[+] Running WhatWeb scan to gather website information...${colors[reset]}"
    whatweb -a 3 "$website_url" | tee "$output_dir/whatweb.txt"
}

# Subdomain discovery and filtering with Katana and ParamSpider integration
find_subdomains_and_endpoints() {
    echo -e "${colors[yellow]}[+] Finding subdomains...${colors[reset]}"
    subfinder -d "$website_input" -all -recursive > "$output_dir/subdomains.txt"
    
    echo -e "${colors[yellow]}[+] Filtering alive subdomains...${colors[reset]}"
    cat "$output_dir/subdomains.txt" | httpx -silent > "$output_dir/alivesub.txt"
    
    echo -e "${colors[yellow]}[+] Checking for subdomain takeover vulnerabilities using Subzy...${colors[reset]}"
    subzy run --targets "$output_dir/subdomains.txt" | tee "$output_dir/subzy_results.txt"
    
    echo -e "${colors[green]}[+] Subdomain takeover detection completed. Results saved in subzy_results.txt.${colors[reset]}"

    echo -e "${colors[yellow]}[+] Crawling alive subdomains using Katana for additional endpoints...${colors[reset]}"
    while IFS= read -r subdomain; do
        echo -e "${colors[blue]}[+] Crawling $subdomain with Katana...${colors[reset]}"
        katana -u "$subdomain" -d 5 -silent -o "$output_dir/katana_endpoints.txt"  # Crawl subdomains with Katana
    done < "$output_dir/alivesub.txt"

    # Run ParamSpider on alive subdomains to gather potential parameters
    paramspider_results_dir="$HOME/aungrecon/results"
    echo -e "${colors[blue]}[+] Clearing previous ParamSpider results in $paramspider_results_dir...${colors[reset]}"
    rm -rf "$paramspider_results_dir"
    mkdir -p "$paramspider_results_dir"
    paramspider -l "$output_dir/alivesub.txt"

    cd "$paramspider_results_dir" || exit
    cat *.txt > allurls.txt  # Combine all ParamSpider results into allurls.txt

    echo -e "${colors[blue]}[+] Combining Katana results with ParamSpider results...${colors[reset]}"
    cat "$output_dir/katana_endpoints.txt" >> allurls.txt  # Append Katana results to allurls.txt

    # Filter combined results for parameterized URLs and truncate parameter values
    echo -e "${colors[blue]}[+] Extracting parameterized URLs and truncating parameters...${colors[reset]}"
    cat allurls.txt | grep '=' | sed 's/=.*/=/' | sort | uniq > "$output_dir/final.txt"  # Sort and remove duplicates
}

# SQLi detection using SQLMap for detection only (no attack)
find_sqli_vulnerabilities() {
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities using BSQLi...${colors[reset]}"

    # Define the path to the BSQLi script
    bsqli_path="$HOME/aungrecon/bsqli/scan.py"

    # Check if BSQLi is properly installed
    if [ ! -f "$bsqli_path" ]; then
        echo -e "${colors[red]}[!] BSQLi tool not found. Please ensure it is installed.${colors[reset]}"
        exit 1
    fi

    # Prepare the output directory for BSQLi results
    bsqli_output_dir="$output_dir/bsqli_results"
    echo -e "${colors[blue]}[+] Clearing previous BSQLi results in $bsqli_output_dir...${colors[reset]}"
    rm -rf "$bsqli_output_dir"
    mkdir -p "$bsqli_output_dir"
    
    # Check if final.txt exists and has parameterized endpoints before running BSQLi
    if [[ -f "$output_dir/final.txt" && -s "$output_dir/final.txt" ]]; then
        # Define paths to URL and payload files
        url_file="$output_dir/bsqli_urls.txt"
        payload_file="$HOME/aungrecon/xor.txt"

        # Copy final.txt to bsqli_urls.txt
        cp "$output_dir/final.txt" "$url_file"

        # Check if payload file exists
        if [[ ! -f "$payload_file" ]]; then
            echo -e "${colors[red]}[!] Payload file not found at $payload_file. Please ensure it exists.${colors[reset]}"
            exit 1
        fi

        echo -e "${colors[blue]}[+] Running BSQLi on URLs from $url_file using payloads from $payload_file...${colors[reset]}"

        # Run BSQLi for the current set of URLs and payloads, preserving color in output
        python3 "$bsqli_path" -u "$url_file" -p "$payload_file" -t 10

        echo -e "${colors[green]}[+] BSQLi detection scan completed.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No parameterized endpoints found in final.txt. Skipping BSQLi detection scan.${colors[reset]}"
    fi
}

# LFI detection for all subdomains using ffuf
run_lfi_scan() {
    echo -e "${colors[yellow]}[+] Testing for LFI vulnerabilities on all subdomains using ffuf...${colors[reset]}"
    
    lfi_payloads="$HOME/aungrecon/lfi.txt"
    
    if [[ -f "$lfi_payloads" ]]; then
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
    echo -e "${colors[yellow]}[+] Testing for Open Redirect vulnerabilities on all alive subdomains using ffuf...${colors[reset]}"
    
    if [[ -f "$HOME/aungrecon/results/allurls.txt" && -s "$HOME/aungrecon/results/allurls.txt" ]]; then
        while IFS= read -r url; do
            echo -e "${colors[blue]}[+] Testing $url for Open Redirect vulnerabilities...${colors[reset]}"
            ffuf -u "$url/FUZZ" -w "$HOME/aungrecon/or.txt" -mc 200 -c -v -mr "http" >> "$output_dir/open_redirect_vul.txt"
        done < "$output_dir/alivesub.txt"
        
        echo -e "${colors[green]}[+] Open Redirect scan completed for all subdomains. Results saved in open_redirect_vul.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No alive subdomains found in alivesub.txt. Skipping Open Redirect scan.${colors[reset]}"
    fi
}

# XSS detection with DalFox using custom payloads
run_xss_scan() {
    echo -e "${colors[yellow]}[+] Finding XSS vulnerabilities using DalFox with custom payloads...${colors[reset]}"
    
    payload_file="$HOME/aungrecon/xss.txt"
    
    if [[ -f "$payload_file" ]]; then
        while IFS= read -r url; do
            echo -e "${colors[blue]}[+] Testing $url for XSS with DalFox and custom payloads...${colors[reset]}"
            dalfox file "$output_dir/final.txt" --silence --custom-payload "$payload_file" --output "$output_dir/xss_vul.txt"
        done < "$output_dir/final.txt"
        
        echo -e "${colors[green]}[+] DalFox XSS scan completed with custom payloads. Results saved in xss_vul.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] Custom payload file not found. Skipping XSS scan.${colors[reset]}"
    fi
}

# Multi-vulnerability detection using Nuclei for all alive subdomains
run_nuclei_scan() {
    echo -e "${colors[yellow]}[+] Running Nuclei for multi-vulnerability scanning on all alive subdomains...${colors[reset]}"
    
    if [[ -f "$output_dir/alivesub.txt" && -s "$output_dir/alivesub.txt" ]]; then
        nuclei -l "$output_dir/alivesub.txt" -t cves,default-logins,exposures,vulnerabilities -severity low,medium,high,critical -o "$output_dir/multiple_vulnerabilities.txt"
        
        echo -e "${colors[green]}[+] Nuclei scan completed. Results saved in multiple_vulnerabilities.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No alive subdomains found in alivesub.txt. Skipping Nuclei scan.${colors[reset]}"
    fi
}

# Cleanup intermediate files
cleanup_files() {
    echo -e "${colors[yellow]}[+] Cleaning up intermediate files...${colors[reset]}"
    rm -f "$output_dir/subdomains.txt" "$output_dir/allurls.txt" "$output_dir/katana_endpoints.txt"
}

# Final output message
output_summary() {
    echo -e "${colors[green]}Filtered URLs have been saved to the respective output files in the 'output' directory:${colors[reset]}"
    echo -e "${colors[cyan]}- XSS: $output_dir/xss_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- Open Redirect: $output_dir/open_redirect_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- LFI: $output_dir/lfi_vul.txt${colors[reset]}"
    echo -e "${colors[cyan]}- SQLi: $output_dir/bsqli_results${colors[reset]}"
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
find_subdomains_and_endpoints  # Discover subdomains, run Katana and ParamSpider
find_sqli_vulnerabilities  # SQLMap scan for detection only (no attack)
run_lfi_scan           # LFI scan using ffuf
run_open_redirect_scan # Open Redirect scan using OpenRedireX
run_xss_scan           # XSS detection with DalFox and custom payloads
run_nuclei_scan
cleanup_files
output_summary
