#!/bin/bash
# Determine script directory dynamically
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$script_dir/tools"
output_dir="$script_dir/output"
paramspider_results_dir="$script_dir/results"
bsqli_output_dir="$output_dir/bsqli_results"
xss_output_dir="$output_dir/xss_results"
lfi_output_dir="$output_dir/lfi_results"
or_output_dir="$output_dir/or_results"
secretfinder_output_dir="$output_dir/secretfinder_results"
nikto_output_dir="$output_dir/nikto_results"
multiple_vulnerabilities_output_dir="$output_dir/multiple_vulnerabilities_results"
whatweb_output_dir="$output_dir/whatweb_results"
subzy_output_dir="$output_dir/subzy_results"
naabu_output_file="$output_dir/naabu_ports_results"
github_repo="https://github.com/aungsanoo-usa/aungrecon.git"
osint_output_dir="$output_dir/osint_results"
GITHUB_TOKENS="$script_dir/github_token.txt"

# Prepare output files before each scan
prepare_output_files() {
    echo -e "${colors[blue]}[+] Preparing and cleaning output files...${colors[reset]}"
    rm -rf "$output_dir" "$paramspider_results_dir"
    mkdir -p "$output_dir" "$paramspider_results_dir" "$bsqli_output_dir" "$whatweb_output_dir" "$xss_output_dir" "$lfi_output_dir" "$or_output_dir" "$secretfinder_output_dir" "$nikto_output_dir" "$multiple_vulnerabilities_output_dir" "$subzy_output_dir" "$osint_output_dir" "$naabu_output_file"
    for file in subdomains.txt alivesub.txt final.txt katana_endpoints.txt; do
        > "$output_dir/$file"
    done
}

tools=(
    "subfinder"           # Subdomain enumeration
    "paramspider"         # Parameter discovery
    "whatweb"             # Web tech fingerprinting
    "uro"                 # URL deduplication
    "httpx"               # HTTP probing
    "subzy"               # Subdomain takeover detection
    "urldedupe"           # URL deduplication tool
    "anew"                # Deduplicate and merge URLs
    "ffuf"                # Fuzzing tool
    "gau"                 # Fetch URLs from public archives
    "gf"                  # Grep patterns for vulnerabilities
    "nuclei"              # Vulnerability scanner
    "dalfox"              # XSS vulnerability scanner
    "katana"              # Web crawling
    "nikto"               # Web server scanner
    "python3"             # Python runtime
    "Gxss"                # Reflection-based XSS scanner
    "kxss"                # Cross-site scripting detection
    "unfurl"              # Extract components from URLs
    "gitdorks_go"         # GitHub dorking
    "enumerepo"           # GitHub repo enumeration
    "porch-pirate"
    "metafinder"
    "emailfinder"
    "whois"
    "jq"
    "jsleak"
    "naabu"
)

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

# Print the banner in blue
echo -e "${colors[yellow]}####################################################################################"
echo -e "##### Welcome to the AungRecon main script #####"
echo -e "####################################################################################${colors[reset]}"

echo -e "${colors[blue]}"
cat << "EOF"
 ▄▄▄       █    ██  ███▄    █   ▄████  ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █ 
▒████▄     ██  ▓██▒ ██ ▀█   █  ██▒ ▀█▒▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ 
▒██  ▀█▄  ▓██  ▒██░▓██  ▀█ ██▒▒██░▄▄▄░▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒
░██▄▄▄▄██ ▓▓█  ░██░▓██▒  ▐▌██▒░▓█  ██▓▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒
 ▓█   ▓██▒▒▒█████▓ ▒██░   ▓██░░▒▓███▀▒░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░
 ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒  ░▒   ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░░░▒░ ░ ░ ░ ░░   ░ ▒░  ░   ░   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ▒    ░░░ ░ ░    ░   ░ ░ ░ ░   ░   ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░ 
      ░  ░   ░              ░       ░    ░        ░  ░░ ░          ░ ░           ░ 
                                                      ░                            
                                                      www.aungsanoo.com
EOF
echo -e "${colors[reset]}"

# Tool check function
check_tools() {
    missing_tools=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${colors[red]}[!] The following tools are missing: ${missing_tools[*]}.${colors[reset]}"
        read -p "[?] Would you like to install them now? (y/n): " install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            ./install.sh || echo -e "${colors[red]}[!] Installation script failed. Please install manually.${colors[reset]}"
        else
            echo -e "${colors[red]}[!] Exiting as required tools are not installed.${colors[reset]}"
            exit 1
        fi
    else
        echo -e "${colors[green]}[+] All required tools are installed.${colors[reset]}"
    fi
}

test_connectivity() {
    echo -e "Checking internet connectivity..."

    # Test multiple known reliable hosts
    for host in google.com cloudflare.com; do
        if nc -zw1 "$host" 443 2>/dev/null; then
            echo -e "Connection to $host: ${bgreen}OK${reset}"
            return
        fi
    done

    # If all tests fail
    echo -e "${bred}[!] Please check your internet connection and then try again...${reset}"
    exit 1
}

# WhatWeb scan
run_whatweb_scan() {
    echo -e "${colors[yellow]}[+] Running WhatWeb scan to gather website information...${colors[reset]}"
    # Run WhatWeb and clean ANSI escape sequences using sed
    whatweb -a 3 "$website_url" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | tee "$whatweb_output_dir/whatweb.txt"
}

run_naabu_scan() {
    echo -e "${colors[yellow]}[+] Running Naabu for port scanning...${colors[reset]}"
    naabu_output_file="$naabu_output_file/naabu_ports.txt"

    # Ensure subdomains.txt exists and is not empty
    if [[ -s "$output_dir/subdomains.txt" ]]; then
        naabu -list "$output_dir/subdomains.txt" -c 50 -nmap-cli 'nmap -sV -sC' -o "$naabu_output_file" || {
            echo -e "${colors[red]}[!] Naabu scan failed.${colors[reset]}"
            return
        }
        echo -e "${colors[green]}[+] Naabu ports scan completed. Results saved in $naabu_output_file.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] subdomains.txt file is missing or empty. Ensure subdomain enumeration is complete before running Naabu.${colors[reset]}"
    fi
}

# Subdomain discovery, takeover check, and URL crawling
find_subdomains_and_endpoints() {
    echo -e "${colors[yellow]}[+] Finding subdomains...${colors[reset]}"
    subfinder -d "$website_input" -all -recursive > "$output_dir/subdomains.txt"
    echo -e "${colors[yellow]}[+] Filtering alive subdomains...${colors[reset]}"
    cat "$output_dir/subdomains.txt" | httpx -silent > "$output_dir/alivesub.txt"
    echo -e "${colors[yellow]}[+] Checking for subdomain takeover vulnerabilities using Subzy...${colors[reset]}"
    subzy run --targets "$output_dir/subdomains.txt" | tee "$subzy_output_dir/subzy_results.txt"
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
    echo -e "${colors[blue]}[+] Filtering URLs for potential bsqli endpoints...${colors[reset]}"
    cat "$output_dir/allurls.txt" | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sed 's/=.*/=/' | sort | uniq > "$output_dir/bsqli_output.txt"
    echo -e "${colors[blue]}[+] Filtering URLs for potential XSS endpoints...${colors[reset]}"
    cat "$output_dir/allurls.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > "$output_dir/xss_output.txt"
    echo -e "${colors[blue]}[+] Filtering URLs for potential Open Redirect endpoints...${colors[reset]}"
    cat "$output_dir/allurls.txt" | gf or | sed 's/=.*/=/' | sort -u > "$output_dir/open_redirect_output.txt"
    echo -e "${colors[blue]}[+] Filtering URLs for potential LFI endpoints...${colors[reset]}"
    cat "$output_dir/allurls.txt" | gf lfi | sed 's/=.*/=/' | sort -u > "$output_dir/lfi_output.txt"
}

# SQLi detection using BSQLi
find_sqli_vulnerabilities() {
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities using the KKonaNN BSQLi scanner...${colors[reset]}"
    bsqli_path="$tools_dir/bsqli/main.py"
    url_file="$output_dir/bsqli_output.txt"
    payload_file="$script_dir/xor.txt"
    output_file="$output_dir/bsqli_results/bsqli_vul.txt"

    # Check if BSQLi tool exists
    if [ ! -f "$bsqli_path" ]; then
        echo -e "${colors[red]}[!] BSQLi tool not found at $bsqli_path. Ensure installation.${colors[reset]}"
        exit 1
    fi

    # Ensure required files exist
    if [ ! -f "$url_file" ] || [ ! -s "$url_file" ]; then
        echo -e "${colors[red]}[!] URL file $url_file is missing or empty. Skipping BSQLi scan.${colors[reset]}"
        return
    fi
    if [ ! -f "$payload_file" ]; then
        echo -e "${colors[red]}[!] Payload file $payload_file is missing. Ensure it exists.${colors[reset]}"
        exit 1
    fi

    # Run the BSQLi scanner
    echo -e "${colors[blue]}[+] Running BSQLi scanner...${colors[reset]}"
    python3 "$bsqli_path" -l "$url_file" -p "$payload_file" -t 10 -s -o "$output_file"

    # Check results
    if [ -s "$output_file" ]; then
        echo -e "${colors[green]}[+] BSQLi vulnerabilities detected. Results saved in $output_file.${colors[reset]}"
    else
        echo -e "${colors[yellow]}[!] BSQLi scan completed, but no vulnerabilities were found.${colors[reset]}"
    fi
}


run_xss_scan() {
    echo -e "${colors[yellow]}[+] Running XSS scan...${colors[reset]}"
    xss_scanner_path="$tools_dir/xss_scanner/xss_scanner.py"
    url_file="$output_dir/xss_output.txt"
    payload_file="$script_dir/xss.txt"
    output_file="$output_dir/xss_results/xss_vul.txt"

    # Check if required files exist
    [ ! -f "$xss_scanner_path" ] && echo -e "${colors[red]}[!] Missing XSS scanner.${colors[reset]}" && exit 1
    [ ! -f "$payload_file" ] && echo -e "${colors[red]}[!] Missing payload file.${colors[reset]}" && exit 1

    # Check if URL file is empty
    if [ ! -s "$url_file" ]; then
        echo -e "${colors[red]}[!] No URLs found in $url_file. Please ensure the file contains valid URLs.${colors[reset]}"
        return
    fi

    # Run the XSS scanner
    python3 "$xss_scanner_path" -l "$url_file" -p "$payload_file" -o "$output_file"

    # Check the results
    if [ -s "$output_file" ]; then
        echo -e "${colors[green]}[+] XSS vulnerabilities detected. Results saved in $output_file.${colors[reset]}"
    else
        echo -e "${colors[yellow]}[!] XSS scan completed but no vulnerabilities found.${colors[reset]}"
    fi
}


run_secretfinder_scan() {
    echo -e "${colors[yellow]}[+] Running SecretFinder...${colors[reset]}"
    secretfinder_path="$tools_dir/SecretFinder/SecretFinder.py"
    js_file="$output_dir/js_links.txt"
    output_file="$output_dir/secretfinder_results/secret.txt"
    grep -E "\.js(\?|$)" "$output_dir/allurls.txt" > "$js_file"
    [ ! -f "$secretfinder_path" ] && echo -e "${colors[red]}[!] Missing SecretFinder.${colors[reset]}" && exit 1
    while IFS= read -r url; do
        python3 "$secretfinder_path" -i "$url" -o cli >> "$output_file"
    done < "$js_file"
}


run_jsleak_scan() {
    echo -e "${colors[yellow]}[+] Running JSLeak to analyze JavaScript files for leaks...${colors[reset]}"
    jsleak_output_file="$output_dir/secretfinder_results/jsleak_output.txt"

    # Ensure js_links.txt exists and is not empty
    if [[ -s "$output_dir/js_links.txt" ]]; then
        cat "$output_dir/js_links.txt" | jsleak -s -l -k > "$jsleak_output_file" || {
            echo -e "${colors[red]}[!] JSLeak scan failed.${colors[reset]}"
            return
        }
        echo -e "${colors[green]}[+] JSLeak scan completed. Results saved in $jsleak_output_file.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] js_links.txt file is missing or empty. Ensure JavaScript links are collected before running JSLeak.${colors[reset]}"
    fi
}

 
run_nikto_scan() {
    echo -e "${colors[yellow]}[+] Running Nikto on subdomains...${colors[reset]}"
    if [[ -s "$output_dir/alivesub.txt" ]]; then
        while IFS= read -r subdomain; do
            nikto -h "$subdomain" -output "$output_dir/nikto_results/nikto_${subdomain//[:\/]/_}.txt"
        done < "$output_dir/alivesub.txt"
    fi
}

run_lfi_scan() {
    echo -e "${colors[yellow]}[+] Running LFI scan...${colors[reset]}"
    
    # Define paths
    lfi_scanner_path="$tools_dir/lfi_scanner/lfi_scan.py"
    url_file="$output_dir/lfi_output.txt"
    payload_file="$script_dir/lfi.txt"
    output_file="$output_dir/lfi_results/lfi_vul.txt"

    # Check if the LFI scanner exists
    if [ ! -f "$lfi_scanner_path" ]; then
        echo -e "${colors[red]}[!] Missing LFI scanner script at $lfi_scanner_path. Run again install.sh ..Skipping.${colors[reset]}"
        return
    fi

    # Check if the payload file exists
    if [ ! -f "$payload_file" ]; then
        echo -e "${colors[red]}[!] Missing payload file at $payload_file. Skipping.${colors[reset]}"
        return
    fi

    # Check if URL file exists and is not empty
    if [ ! -s "$url_file" ]; then
        echo -e "${colors[red]}[!] No URLs to scan in $url_file. Skipping.${colors[reset]}"
        return
    fi

    # Run the LFI scanner
    echo -e "${colors[blue]}[+] Scanning for LFI vulnerabilities using $lfi_scanner_path...${colors[reset]}"
    if python3 "$lfi_scanner_path" -l "$url_file" -p "$payload_file" -o "$output_file"; then
        if [ -s "$output_file" ]; then
            echo -e "${colors[green]}[+] LFI scan completed. Results saved to $output_file.${colors[reset]}"
        else
            echo -e "${colors[yellow]}[!] LFI scan completed but no vulnerabilities were found.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] An error occurred while running the LFI scanner.${colors[reset]}"
    fi
}


run_open_redirect_scan() {
    echo -e "${colors[yellow]}[+] Running Open Redirect scan...${colors[reset]}"
    [[ -s "$output_dir/alivesub.txt" ]] && while IFS= read -r url; do ffuf -u "$url/FUZZ" -w "$script_dir/or.txt" -mc 200 -c -v -mr "http" >> "$output_dir/or_results/open_redirect_vul.txt"; done < "$output_dir/alivesub.txt"
}

run_nuclei_scan() {
    echo -e "${colors[yellow]}[+] Running Nuclei scan...${colors[reset]}"
    [[ -s "$output_dir/alivesub.txt" ]] && nuclei -l "$output_dir/alivesub.txt" -t $tools_dir/priv8-Nuclei -o "$output_dir/multiple_vulnerabilities_results/multiple_vulnerabilities.txt"
}

run_corsy_scan() {
    echo -e "${colors[yellow]}[+] Running Corsy for CORS misconfiguration detection...${colors[reset]}"
    corsy_output_file="$output_dir/corsy_results/corsy_vul.txt"

    # Ensure alivesub.txt exists and is not empty
    if [[ -s "$output_dir/alivesub.txt" ]]; then
        mkdir -p "$output_dir/corsy_results"
        python3 "$tools_dir/Corsy/corsy.py" -i "$output_dir/alivesub.txt" -o "$corsy_output_file" || {
            echo -e "${colors[red]}[!] Corsy scan failed.${colors[reset]}"
            return
        }
        echo -e "${colors[green]}[+] Corsy scan completed. Results saved in $corsy_output_file.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] alivesub.txt file is missing or empty. Ensure subdomain enumeration is complete before running Corsy.${colors[reset]}"
    fi
}


output_summary() {
    echo -e "${colors[green]}Filtered URLs and vulnerabilities saved in the 'output' directory:${colors[reset]}"

    # Loop through all non-empty files in the output directory (including subdirectories)
    find "$output_dir" -type f -size +0c | while read -r file; do
        # Display file paths relative to the output directory for cleaner output
        relative_file="${file#$output_dir/}"
        echo -e "${colors[cyan]}- $relative_file${colors[reset]}"
    done
}

# OSINT Functions
# Load GitHub Token
GITHUB_TOKEN=""
if [[ -f "github_token.txt" ]]; then
    GITHUB_TOKEN=$(head -n 1 github_token.txt)
    echo -e "${colors[green]}[+] GitHub token loaded successfully.${colors[reset]}"
else
    echo -e "${colors[red]}[!] GitHub token file not found. Exiting.${colors[reset]}"
fi

# Validate Token
validate_github_token() {
    response=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user)
    if [[ "$response" -ne 200 ]]; then
        echo -e "${colors[red]}[!] Invalid or expired GitHub token. Please update github_token.txt.${colors[reset]}"
      
    else
        echo -e "${colors[green]}[+] GitHub token is valid.${colors[reset]}"
    fi
}
validate_github_token

# Use the token with tools
github_repos() {
    echo -e "${colors[yellow]}[+] Running GitHub Repos Analysis...${colors[reset]}"
    mkdir -p .tmp "$osint_output_dir"
    echo "$website_input" | unfurl format %r > .tmp/company_name.txt
    enumerepo -token-string "$GITHUB_TOKEN" -usernames .tmp/company_name.txt -o .tmp/company_repos.txt
    if [[ -s .tmp/company_repos.txt ]]; then
        echo -e "${colors[green]}[+] Results saved to $osint_output_dir/github_company_secrets.json.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No repositories found for analysis.${colors[reset]}"
    fi
}

github_dorks() {
    echo -e "${colors[yellow]}[+] Running GitHub Dorks Analysis...${colors[reset]}"
    mkdir -p "$osint_output_dir"

    # Check if GitHub token file exists and is not empty
    if [[ ! -s "$GITHUB_TOKENS" ]]; then
        echo -e "${colors[red]}[!] GitHub token file is missing or empty: $GITHUB_TOKENS${colors[reset]}"
        read -p "[?] Enter your GitHub token: " user_token
        if [[ -z "$user_token" ]]; then
            echo -e "${colors[red]}[!] No token provided. Skipping GitHub Dorks analysis.${colors[reset]}"
            return
        else
            echo "$user_token" > "$GITHUB_TOKENS"
            echo -e "${colors[green]}[+] Token saved to $GITHUB_TOKENS.${colors[reset]}"
        fi
    fi

    # Validate token file content
    token=$(head -1 "$GITHUB_TOKENS")
    if [[ -z "$token" ]]; then
        echo -e "${colors[red]}[!] Token file is empty. Skipping GitHub Dorks analysis.${colors[reset]}"
        return
    fi

    # Set dorks file paths
    medium_dorks="${tools_dir}/gitdorks_go/Dorks/medium_dorks.txt"
    small_dorks="${tools_dir}/gitdorks_go/Dorks/smalldorks.txt"
    output_file="$osint_output_dir/gitdorks.txt"

    # Ensure gitdorks_go exists
    if ! command -v gitdorks_go &>/dev/null; then
        echo -e "${colors[red]}[!] gitdorks_go not found. Please ensure it is installed.${colors[reset]}"
        return
    fi

    # Choose dorks file based on depth
    dorks_file="$small_dorks"
    [[ "$DEEP" == true ]] && dorks_file="$medium_dorks"

    if [[ -f "$dorks_file" ]]; then
        echo -e "${colors[cyan]}[+] Performing GitHub Dorks analysis...${colors[reset]}"
        gitdorks_go -gd "$dorks_file" -nws 20 -target "$website_input" -token "$token" -ew 3 | anew -q "$output_file" || {
            echo -e "${colors[red]}[!] gitdorks_go command failed.${colors[reset]}"
            return
        }
        if [[ -s "$output_file" ]]; then
            echo -e "${colors[green]}[+] GitHub Dorks analysis completed. Results saved to $output_file.${colors[reset]}"
        else
            echo -e "${colors[yellow]}[!] No results found during GitHub Dorks analysis.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] Dorks file not found: $dorks_file${colors[reset]}"
    fi
}

metadata() {
    echo -e "${colors[yellow]}[+] Running Metadata Analysis...${colors[reset]}"
    metafinder -d "$website_input" -l 20 -o "$osint_output_dir" -go -bi || echo "Metafinder command failed"
    echo -e "${colors[green]}[+] Results saved to $osint_output_dir/metadata_results.txt.${colors[reset]}"
}

apileaks() {
    echo -e "${colors[yellow]}[+] Running API Leaks Analysis...${colors[reset]}"
    mkdir -p "$osint_output_dir"

    # Porch-Pirate Analysis
    if command -v porch-pirate &>/dev/null; then
        echo -e "${colors[cyan]}[+] Running Porch-Pirate for Postman API leaks...${colors[reset]}"
        porch-pirate -s "$website_input" --dump 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$osint_output_dir/postman_leaks.txt"
        if [[ -s "$osint_output_dir/postman_leaks.txt" ]]; then
            echo -e "${colors[green]}[+] Porch-Pirate completed. Results saved to $osint_output_dir/postman_leaks.txt.${colors[reset]}"
        else
            echo -e "${colors[yellow]}[!] No leaks found by Porch-Pirate.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] Porch-Pirate not found. Skipping Postman API leak analysis.${colors[reset]}"
    fi

    # SwaggerSpy Analysis
    swagger_spy_path="${tools_dir}/SwaggerSpy/swaggerspy.py"
    if [[ -f "$swagger_spy_path" ]]; then
        echo -e "${colors[cyan]}[+] Running SwaggerSpy for Swagger API leaks...${colors[reset]}"
        python3 "$swagger_spy_path" "$website_input" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$osint_output_dir/swagger_leaks.txt"
        if [[ -s "$osint_output_dir/swagger_leaks.txt" ]]; then
            echo -e "${colors[green]}[+] SwaggerSpy completed. Results saved to $osint_output_dir/swagger_leaks.txt.${colors[reset]}"
        else
            echo -e "${colors[yellow]}[!] No leaks found by SwaggerSpy.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] SwaggerSpy not found. Skipping Swagger API leak analysis.${colors[reset]}"
    fi

    echo -e "${colors[green]}[+] API Leaks Analysis completed.${colors[reset]}"
}



emails() {
    echo -e "${colors[yellow]}[+] Running Email Enumeration...${colors[reset]}"
    if command -v emailfinder &>/dev/null; then
        emailfinder -d "$website_input" > "$osint_output_dir/emails.txt" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "${colors[red]}[!] Emailfinder encountered an error. Ensure fonts are properly installed.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] Emailfinder not found. Skipping email enumeration.${colors[reset]}"
    fi

    if [ -f "${tools_dir}/LeakSearch/LeakSearch.py" ]; then
        python3 "$tools_dir/LeakSearch/LeakSearch.py" -k "$website_input" -o "$osint_output_dir/passwords.txt" || echo "LeakSearch command failed"
    else
        echo -e "${colors[red]}[!] LeakSearch not found. Skipping password enumeration.${colors[reset]}"
    fi
    echo -e "${colors[green]}[+] Results saved to $osint_output_dir/emails.txt and $osint_output_dir/passwords.txt.${colors[reset]}"
}


domain_info() {
    echo -e "${colors[yellow]}[+] Gathering Domain Information...${colors[reset]}"
    
    # WHOIS Information
    whois -H "$website_input" > "$osint_output_dir/domain_info_general.txt"
    echo -e "${colors[green]}[+] WHOIS information saved to $osint_output_dir/domain_info_general.txt.${colors[reset]}"
    
    # Attempt Azure Tenant Info via Microsoft Graph API
    echo -e "${colors[yellow]}[+] Gathering Azure Tenant Information...${colors[reset]}"
    azure_info=$(curl -s "https://login.microsoftonline.com/${website_input}/v2.0/.well-known/openid-configuration" | jq -r '.authorization_endpoint' 2>/dev/null)
    if [[ -n "$azure_info" && "$azure_info" != "null" ]]; then
        echo "$azure_info" > "$osint_output_dir/azure_tenant_info.txt"
        echo -e "${colors[green]}[+] Azure tenant information saved to $osint_output_dir/azure_tenant_info.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] Unable to retrieve Azure tenant information.${colors[reset]}"
    fi

    # Azure DNS Records
    echo -e "${colors[yellow]}[+] Checking DNS records for Azure verification...${colors[reset]}"
    dig txt "$website_input" +short | grep 'MS=' > "$osint_output_dir/azure_dns_records.txt"
    if [[ -s "$osint_output_dir/azure_dns_records.txt" ]]; then
        echo -e "${colors[green]}[+] Azure DNS verification records saved to $osint_output_dir/azure_dns_records.txt.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No Azure DNS verification records found.${colors[reset]}"
    fi
    
    # Run Dorks Hunter
    echo -e "${colors[cyan]}[+] Running Dorks Hunter for Google Dorks...${colors[reset]}"
    python3 "$tools_dir/dorks_hunter/dorks_hunter.py" -d "$website_input" -o "$osint_output_dir/dorks.txt"
    if [[ -s "$osint_output_dir/dorks.txt" ]]; then
       echo -e "${colors[green]}[+] Dorks Hunter completed. Results saved to $osint_output_dir/dorks.txt.${colors[reset]}"
   else
    echo -e "${colors[yellow]}[!] Dorks Hunter did not find any results.${colors[reset]}"
   fi
}

spoof() {
    echo -e "${colors[yellow]}[+] Searching for Spoofable Domains...${colors[reset]}"
    python3 "$tools_dir/Spoofy/spoofy.py" -d "$website_input" > "$osint_output_dir/spoof.txt"
    echo -e "${colors[green]}[+] Results saved to $osint_output_dir/spoof.txt.${colors[reset]}"
}

third_party_misconfigs() {
    echo -e "${colors[yellow]}[+] Searching for Third-Party Misconfigurations...${colors[reset]}"

    # Define the misconfig-mapper binary and templates paths
    misconfig_mapper_path="$tools_dir/misconfig-mapper/misconfig-mapper"
    misconfig_templates_path="$tools_dir/misconfig-mapper/templates/services.json"

    # Ensure the misconfig-mapper binary exists
    if [[ -x "$misconfig_mapper_path" ]]; then
        # Update templates before running
        echo -e "${colors[cyan]}[+] Updating Misconfig Mapper templates...${colors[reset]}"
        "$misconfig_mapper_path" -update-templates || {
            echo -e "${colors[red]}[!] Failed to update Misconfig Mapper templates.${colors[reset]}"
            return
        }

        # Check if templates exist
        if [[ -f "$misconfig_templates_path" ]]; then
            company_name=$(echo "$website_input" | unfurl format %r)
            echo -e "${colors[cyan]}[+] Running Misconfig Mapper...${colors[reset]}"
            "$misconfig_mapper_path" -target "$company_name" -service "*" > "$osint_output_dir/third_party_misconfigs.txt"

            # Check if results were generated
            if [[ -s "$osint_output_dir/third_party_misconfigs.txt" ]]; then
                echo -e "${colors[green]}[+] Results saved to $osint_output_dir/third_party_misconfigs.txt.${colors[reset]}"
            else
                echo -e "${colors[yellow]}[!] No misconfigurations found.${colors[reset]}"
            fi
        else
            echo -e "${colors[red]}[!] Templates not found in $misconfig_templates_path. Misconfig Mapper cannot run.${colors[reset]}"
        fi
    else
        echo -e "${colors[red]}[!] Misconfig Mapper binary not found at $misconfig_mapper_path. Skipping analysis.${colors[reset]}"
    fi
}


ip_info() {
    echo -e "${colors[yellow]}[+] Gathering IP Information...${colors[reset]}"
    mkdir -p "$osint_output_dir"
    curl "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${website_input}" > "$osint_output_dir/ip_info.json"
    echo -e "${colors[green]}[+] Results saved to $osint_output_dir/ip_info.json.${colors[reset]}"
}

# Check general internet connectivity
test_connectivity
check_tools
read -p "[+] Enter the website domain: " website_input
website_url="${website_input#http://}"
website_url="${website_input#https://}"
website_url="https://$website_url"


# Flag to check if Option 1 has been executed
subdomains_discovered=false

# Trap for SIGINT (Ctrl+Shift+C)
trap ctrl_c SIGINT

ctrl_c() {
    echo -e "\n${colors[yellow]}[!] Detected Ctrl+Shift+C.${colors[reset]}"
    while true; do
        read -p "(s)kip, (c)ontinue, or (q)uit: " choice
        case $choice in
            s|S)
                echo -e "${colors[green]}[+] Skipping current operation and returning to menu.${colors[reset]}"
                menu ;;
            c|C)
                echo -e "${colors[green]}[+] Continuing current operation.${colors[reset]}"
                return ;;
            q|Q)
                echo -e "${colors[red]}[!] Quitting script.${colors[reset]}"
                exit 0 ;;
            *)
                echo -e "${colors[red]}[!] Invalid choice. Please select (s), (c), or (q).${colors[reset]}"
        esac
    done
}

# Main menu
menu() {
    echo -e "${colors[cyan]}Select an option:${colors[reset]}"
    echo "1. Crawl URLs and Endpoints (Katana + ParamSpider)"
    echo "2. Scan for Blind SQL Injection Vulnerabilities"
    echo "3. Scan for XSS Vulnerabilities"
    echo "4. Scan for Open Redirect & CORS misconfiguration detection "
    echo "5. Scan for LFI Vulnerabilities"
    echo "6. Scan for Sensitive Data (apikeys, tokens, etc.)"
    echo "7. Run OSINT Tools (API leak, Emails, Misconfig, Domain Info, etc.)"
    echo "8. Perform Full Scan"
    echo "9. Update Tool"
    echo "10. Exit"
    read -p "Enter your choice [1-10]: " choice

    case $choice in
        1)
            echo -e "${colors[yellow]}[+] Starting URL Crawling and Endpoint Discovery...${colors[reset]}"
            prepare_output_files
            run_whatweb_scan
            find_subdomains_and_endpoints
            run_naabu_scan
            subdomains_discovered=true
            echo -e "${colors[green]}[+] URL Crawling completed. Returning to menu.${colors[reset]}"
            menu ;;
            
        2)
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[red]}[!] Option 1 has not been executed. Running Option 1 first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                find_subdomains_and_endpoints
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting Blind SQL Injection Scan...${colors[reset]}"
            find_sqli_vulnerabilities
            menu ;;
            
        3)
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[red]}[!] Option 1 has not been executed. Running Option 1 first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                find_subdomains_and_endpoints
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting XSS Scan...${colors[reset]}"
            run_xss_scan
            menu ;;
            
        4)
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[red]}[!] Option 1 has not been executed. Running Option 1 first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                find_subdomains_and_endpoints
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting Open Redirect Scan...${colors[reset]}"
            run_open_redirect_scan
            run_corsy_scan
            menu ;;
            
        5)
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[red]}[!] Option 1 has not been executed. Running Option 1 first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                find_subdomains_and_endpoints
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting LFI Scan...${colors[reset]}"
            run_lfi_scan
            menu ;; 
            
        6)
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[red]}[!] Option 1 has not been executed. Running Option 1 first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                find_subdomains_and_endpoints
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting Secret Finder Scan...${colors[reset]}"
            run_secretfinder_scan
            run_jsleak_scan
            menu ;;    
            
        7) 
            if [ "$subdomains_discovered" != true ]; then
                echo -e "${colors[yellow]}[!] Preparing and cleaning output files first...${colors[reset]}"
                prepare_output_files
                run_whatweb_scan
                subdomains_discovered=true
            fi
            echo -e "${colors[yellow]}[+] Starting OSINT Tools...${colors[reset]}"
            github_repos
            github_dorks
            metadata
            apileaks
            emails
            domain_info
            third_party_misconfigs
            spoof
            ip_info
            echo -e "${colors[green]}[+] OSINT Tools completed. Results saved in $osint_output_dir.${colors[reset]}"
            menu;;    
            
        8)
            if [ "$subdomains_discovered" != true ]; then
            echo -e "${colors[yellow]}[+] Starting Full Scan (includes Option 1)...${colors[reset]}"
            prepare_output_files
            run_whatweb_scan
            find_subdomains_and_endpoints
            run_naabu_scan
            find_sqli_vulnerabilities
            run_xss_scan
            run_open_redirect_scan
            run_corsy_scan
            run_secretfinder_scan
            run_jsleak_scan
            run_lfi_scan
            run_secretfinder_scan
            run_nikto_scan
            run_nuclei_scan
            github_repos
            github_dorks
            metadata
            apileaks
            emails
            domain_info
            third_party_misconfigs
            spoof
            ip_info
            subdomains_discovered=true
	    fi
            echo -e "${colors[yellow]}[+] Starting Full Scan...${colors[reset]}"
            run_nikto_scan
            run_nuclei_scan
            output_summary
            echo -e "${colors[green]}Full Scan completed.${colors[reset]}"
            menu ;;
        9) update_tool ;;
        10) echo -e "${colors[green]}Exiting...${colors[reset]}" ; exit 0 ;;
        *) echo -e "${colors[red]}Invalid option, try again.${colors[reset]}" ; menu ;;
    esac
}


# Function: Check if subdomain discovery has been performed before running other scans
check_crawl_and_execute() {
    local func=$1
    local scan_name=$2
    if [ "$subdomains_discovered" = true ]; then
        echo -e "${colors[yellow]}Starting $scan_name...${colors[reset]}"
        $func
    else
        echo -e "${colors[red]}[!] Subdomain discovery has not been performed. Please run Option 1 first.${colors[reset]}"
        menu
    fi
}

# Function: Update Tool
update_tool() {
    echo -e "${colors[blue]}[+] Updating AungRecon Tool...${colors[reset]}"
    cd "$script_dir" || exit

    # Stash local changes
    if ! git diff --quiet; then
        echo -e "${colors[yellow]}[!] Stashing local changes...${colors[reset]}"
        git stash || echo -e "${colors[red]}[!] Failed to stash changes.${colors[reset]}"
    fi

    # Pull updates
    git pull "$github_repo" || {
        echo -e "${colors[red]}[!] Failed to pull updates. Please check your network connection or resolve conflicts manually.${colors[reset]}"
        return
    }

    # Reapply stashed changes
    if git stash list | grep -q "stash@{0}"; then
        echo -e "${colors[yellow]}[!] Reapplying stashed changes...${colors[reset]}"
        git stash pop || echo -e "${colors[red]}[!] Failed to reapply stashed changes. Resolve conflicts manually.${colors[reset]}"
    fi

    # Ensure the script remains executable
    chmod +x "$(basename "$0")"
    echo -e "${colors[green]}[+] Tool updated successfully.${colors[reset]}"
    menu
}


# Show the menu immediately upon running the script
menu
