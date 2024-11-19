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
paramspider_results_dir="$HOME/aungrecon/results"
bsqli_output_dir="$output_dir/bsqli_results"
github_repo="https://github.com/aungsanoo-usa/aungrecon.git"
script_dir="$HOME/aungrecon"  # Path where the repository is cloned
temp_file="/tmp/aungrecon_state.txt"  # File to store current script state

tools=("subfinder" "paramspider" "whatweb" "uro" "httpx" "subzy" "urldedupe" "anew" "ffuf" "gau" "gf" "nuclei" "dalfox" "katana" "nikto" "python3")

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

update_and_restart() {
    echo -e "${colors[yellow]}[+] Checking for updates...${colors[reset]}"
    
    if ! command -v git &>/dev/null; then
        echo -e "${colors[red]}[!] Git is not installed. Please install git to use the update function.${colors[reset]}"
        exit 1
    fi

    echo "$current_stage" > "$temp_file"
    cd "$script_dir" || exit

    if ! git diff --quiet; then
        echo -e "${colors[red]}[!] Uncommitted changes detected. Stashing changes temporarily to allow updates.${colors[reset]}"
        git stash
    fi

    git fetch origin
    if git diff --quiet HEAD origin/main; then
        echo -e "${colors[green]}[+] Script is up-to-date.${colors[reset]}"
    else
        echo -e "${colors[blue]}[+] Updates found. Pulling the latest changes...${colors[reset]}"
        git pull origin main
        
        # Run chmod only once, if permissions are incorrect
        if [[ ! -x "$script_dir/aungrecon.sh" ]]; then
            chmod +x "$script_dir/aungrecon.sh"
            echo -e "${colors[green]}[+] Script permissions updated!${colors[reset]}"
        fi

        if git stash list | grep -q "stash@{0}"; then
            echo -e "${colors[yellow]}[+] Reapplying stashed changes...${colors[reset]}"
            git stash pop
        fi

        exec "$0"
    fi
}
# Prepare output files before each scan
prepare_output_files() {
    echo -e "${colors[blue]}[+] Preparing and cleaning output files...${colors[reset]}"
    rm -rf "$output_dir" "$paramspider_results_dir"
    mkdir -p "$output_dir" "$paramspider_results_dir" "$bsqli_output_dir"
    for file in xss_vul.txt open_redirect_vul.txt lfi_vul.txt multiple_vulnerabilities.txt subdomains.txt alivesub.txt final.txt whatweb.txt katana_endpoints.txt subzy_results.txt secret.txt; do
        > "$output_dir/$file"
    done
}
# WhatWeb scan
run_whatweb_scan() {
    echo -e "${colors[yellow]}[+] Running WhatWeb scan to gather website information...${colors[reset]}"
    whatweb -a 3 "$website_url" | tee "$output_dir/whatweb.txt"
}

# Subdomain discovery, takeover check, and URL crawling
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
        katana -u "$subdomain" -d 5 -silent -o "$output_dir/katana_endpoints.txt"
    done < "$output_dir/alivesub.txt"
    
    # ParamSpider scan for parameterized URLs
    echo -e "${colors[blue]}[+] Clearing previous ParamSpider results...${colors[reset]}"
    rm -rf "$paramspider_results_dir"
    mkdir -p "$paramspider_results_dir"
    paramspider -l "$output_dir/alivesub.txt"
    cat "$paramspider_results_dir"/*.txt > "$output_dir/allurls.txt"
    
    # Combine results
    echo -e "${colors[blue]}[+] Combining Katana results with ParamSpider results...${colors[reset]}"
    cat "$output_dir/katana_endpoints.txt" >> "$output_dir/allurls.txt"
    echo -e "${colors[blue]}[+] Filtering parameterized URLs...${colors[reset]}"
    cat "$output_dir/allurls.txt" | grep '=' | sed 's/=.*/=/' | sort | uniq > "$output_dir/final.txt"
}

# SQLi detection using BSQLi
find_sqli_vulnerabilities() {
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities using BSQLi...${colors[reset]}"
    bsqli_path="$HOME/aungrecon/bsqli/scan.py"
    if [ ! -f "$bsqli_path" ]; then
        echo -e "${colors[red]}[!] BSQLi tool not found. Ensure installation.${colors[reset]}"
        exit 1
    fi
    if [[ -f "$output_dir/final.txt" && -s "$output_dir/final.txt" ]]; then
        url_file="$output_dir/bsqli_urls.txt"
        proxy_file="$HOME/aungrecon/proxy.txt"
        payload_file="$HOME/aungrecon/xor.txt"
        cp "$output_dir/final.txt" "$url_file"
        [ ! -f "$payload_file" ] && echo -e "${colors[red]}[!] Missing payload file.${colors[reset]}" && exit 1
        python3 "$bsqli_path" -u "$url_file" -p "$payload_file" -t 5 --proxy-file "$proxy_file"
        mv "$HOME/aungrecon/bsqli/output/"*.html "$bsqli_output_dir/" 2>/dev/null
        echo -e "${colors[green]}[+] HTML report moved to $bsqli_output_dir.${colors[reset]}"
    fi
}

run_xss_scan() {
    echo -e "${colors[yellow]}[+] Running XSS scan...${colors[reset]}"
    xss_scanner_path="$HOME/aungrecon/xss_scanner/xss_scanner.py"
    url_file="$output_dir/final.txt"
    payload_file="$HOME/aungrecon/xss.txt"
    output_file="$output_dir/xss_vul.txt"
    [ ! -f "$xss_scanner_path" ] && echo -e "${colors[red]}[!] Missing XSS scanner.${colors[reset]}" && exit 1
    [ ! -f "$payload_file" ] && echo -e "${colors[red]}[!] Missing payload file.${colors[reset]}" && exit 1
    [ -s "$url_file" ] && python3 "$xss_scanner_path" -l "$url_file" -p "$payload_file" -o "$output_file"
}

run_secretfinder_scan() {
    echo -e "${colors[yellow]}[+] Running SecretFinder...${colors[reset]}"
    secretfinder_path="$HOME/aungrecon/SecretFinder/SecretFinder.py"
    js_file="$output_dir/js_links.txt"
    output_file="$output_dir/secret.txt"
    grep -E "\.js(\?|$)" "$output_dir/allurls.txt" > "$js_file"
    [ ! -f "$secretfinder_path" ] && echo -e "${colors[red]}[!] Missing SecretFinder.${colors[reset]}" && exit 1
    while IFS= read -r url; do
        python3 "$secretfinder_path" -i "$url" -o cli >> "$output_file"
    done < "$js_file"
}

run_nikto_scan() {
    echo -e "${colors[yellow]}[+] Running Nikto on subdomains...${colors[reset]}"
    if [[ -s "$output_dir/alivesub.txt" ]]; then
        while IFS= read -r subdomain; do
            nikto -h "$subdomain" -output "$output_dir/nikto_${subdomain//[:\/]/_}.txt"
        done < "$output_dir/alivesub.txt"
    fi
}

run_lfi_scan() {
    echo -e "${colors[yellow]}[+] Running LFI scan...${colors[reset]}"
    lfi_payloads="$HOME/aungrecon/lfi.txt"
    [[ -f "$lfi_payloads" ]] && while IFS= read -r url; do gau "$url" | gf lfi | ffuf -u {} -w "$lfi_payloads" -c -mr "root:x:0:" -o "$output_dir/lfi_vul.txt"; done < "$output_dir/alivesub.txt"
}

run_open_redirect_scan() {
    echo -e "${colors[yellow]}[+] Running Open Redirect scan...${colors[reset]}"
    [[ -s "$output_dir/alivesub.txt" ]] && while IFS= read -r url; do ffuf -u "$url/FUZZ" -w "$HOME/aungrecon/or.txt" -mc 200 -c -v -mr "http" >> "$output_dir/open_redirect_vul.txt"; done < "$output_dir/alivesub.txt"
}

run_nuclei_scan() {
    echo -e "${colors[yellow]}[+] Running Nuclei scan...${colors[reset]}"
    [[ -s "$output_dir/alivesub.txt" ]] && nuclei -l "$output_dir/alivesub.txt" -t $HOME/aungrecon/priv8-Nuclei -o "$output_dir/multiple_vulnerabilities.txt"
}

output_summary() {
    echo -e "${colors[green]}Filtered URLs and vulnerabilities saved in the 'output' directory:${colors[reset]}"
    for file in xss_vul.txt open_redirect_vul.txt lfi_vul.txt final.txt whatweb.txt subzy_results.txt secret.txt multiple_vulnerabilities.txt secret.txt; do
        [[ -s "$output_dir/$file" ]] && echo -e "${colors[cyan]}- $file: $output_dir/$file${colors[reset]}"
    done
}

update_and_restart
check_tools
read -p "[+] Enter the website domain: " website_input
website_url="${website_input#http://}"
website_url="${website_input#https://}"
website_url="https://$website_url"

prepare_output_files
run_whatweb_scan
find_subdomains_and_endpoints
find_sqli_vulnerabilities
run_xss_scan
run_secretfinder_scan
run_nikto_scan
run_lfi_scan
run_open_redirect_scan
run_nuclei_scan
output_summary
