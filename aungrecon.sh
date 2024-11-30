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
# Determine script directory dynamically
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output_dir="$script_dir/output"
paramspider_results_dir="$script_dir/results"
bsqli_output_dir="$output_dir/bsqli_results"
github_repo="https://github.com/aungsanoo-usa/aungrecon.git"
# Ensure required directories exist
mkdir -p "$output_dir" "$paramspider_results_dir" "$bsqli_output_dir"

tools=("subfinder" "paramspider" "whatweb" "uro" "httpx" "subzy" "urldedupe" "anew" "ffuf" "gau" "gf" "nuclei" "dalfox" "katana" "nikto" "python3" "Gxss" "kxss")

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
    echo -e "${colors[yellow]}[+] Finding SQLi vulnerabilities using BSQLi...${colors[reset]}"
    bsqli_path="$script_dir/bsqli/scan.py"
    if [ ! -f "$bsqli_path" ]; then
        echo -e "${colors[red]}[!] BSQLi tool not found. Ensure installation.${colors[reset]}"
        exit 1
    fi

    if [[ -f "$output_dir/bsqli_output.txt" && -s "$output_dir/bsqli_output.txt" ]]; then
        url_file="$output_dir/bsqli_output.txt"
        proxy_file="$script_dir/proxy.txt"
        payload_file="$script_dir/xor.txt"

        # Ensure payload file exists
        if [ ! -f "$payload_file" ]; then
            echo -e "${colors[red]}[!] Missing payload file.${colors[reset]}"
            exit 1
        fi

        # Run the BSQLi scanner
        python3 "$bsqli_path" -u "$url_file" -p "$payload_file" -t 5 --proxy-file "$proxy_file"

        # Move only non-empty HTML reports
        for file in "$script_dir/bsqli/output/"*.html; do
            if [ -s "$file" ]; then
                echo "Moving report: $file"
                mv "$file" "$bsqli_output_dir/" 2>/dev/null
            else
                echo "Skipping empty or incomplete report: $file"
            fi
        done

        echo -e "${colors[green]}[+] HTML report(s) moved to $bsqli_output_dir.${colors[reset]}"
    else
        echo -e "${colors[red]}[!] No URLs found in $output_dir/bsqli_output.txt or the file is empty.${colors[reset]}"
    fi
}

run_xss_scan() {
    echo -e "${colors[yellow]}[+] Running XSS scan...${colors[reset]}"
    xss_scanner_path="$script_dir/xss_scanner/xss_scanner.py"
    url_file="$output_dir/xss_output.txt"
    payload_file="$script_dir/xss.txt"
    output_file="$output_dir/xss_vul.txt"

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
    secretfinder_path="$script_dir/SecretFinder/SecretFinder.py"
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
    
    # Define paths
    lfi_scanner_path="$script_dir/lfi_scanner/lfi_scan.py"
    url_file="$output_dir/lfi_output.txt"
    payload_file="$script_dir/lfi.txt"
    output_file="$output_dir/lfi_vul.txt"

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
    [[ -s "$output_dir/alivesub.txt" ]] && while IFS= read -r url; do ffuf -u "$url/FUZZ" -w "$script_dir/or.txt" -mc 200 -c -v -mr "http" >> "$output_dir/open_redirect_vul.txt"; done < "$output_dir/alivesub.txt"
}

run_nuclei_scan() {
    echo -e "${colors[yellow]}[+] Running Nuclei scan...${colors[reset]}"
    [[ -s "$output_dir/alivesub.txt" ]] && nuclei -l "$output_dir/alivesub.txt" -t $script_dir/priv8-Nuclei -o "$output_dir/multiple_vulnerabilities.txt"
}

output_summary() {
    echo -e "${colors[green]}Filtered URLs and vulnerabilities saved in the 'output' directory:${colors[reset]}"
    for file in xss_vul.txt open_redirect_vul.txt lfi_vul.txt final.txt whatweb.txt subzy_results.txt secret.txt multiple_vulnerabilities.txt secret.txt; do
        [[ -s "$output_dir/$file" ]] && echo -e "${colors[cyan]}- $file: $output_dir/$file${colors[reset]}"
    done
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
    echo -e "\n${colors[cyan]}Select an option:${colors[reset]}"
    echo -e "1. Crawl URLs and Endpoints (Katana + ParamSpider)"
    echo -e "2. Scan for Blind SQL Injection Vulnerabilities"
    echo -e "3. Scan for XSS Vulnerabilities"
    echo -e "4. Scan for Open Redirect Vulnerabilities"
    echo -e "5. Scan for LFI Vulnerabilities"
    echo -e "6. Scan for Sensitive data (apikeys,accesstoken,authorizations)"
    echo -e "7. Perform Full Scan"
    echo -e "8. Update Tool"
    echo -e "9. Exit"
    read -p "Enter your choice [1-7]: " choice

    case $choice in
        1)
            echo -e "${colors[yellow]}[+] Starting URL Crawling and Endpoint Discovery...${colors[reset]}"
            prepare_output_files
            run_whatweb_scan
            find_subdomains_and_endpoints
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
            menu ;;    
            
            
        7)
            if [ "$subdomains_discovered" != true ]; then
            echo -e "${colors[yellow]}[+] Starting Full Scan (includes Option 1)...${colors[reset]}"
            prepare_output_files
            run_whatweb_scan
            find_subdomains_and_endpoints
            subdomains_discovered=true
	    fi
            echo -e "${colors[yellow]}[+] Starting Full Scan...${colors[reset]}"
            find_sqli_vulnerabilities
            run_xss_scan
            run_open_redirect_scan
            run_secretfinder_scan
            run_lfi_scan
            run_secretfinder_scan
            run_nikto_scan
            run_nuclei_scan
            output_summary
            menu ;;
        8) update_tool ;;
        9) echo -e "${colors[green]}Exiting...${colors[reset]}" ; exit 0 ;;
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

# Function: Perform Full Scan
full_scan() {
    echo -e "${colors[yellow]}Starting Full Scan...${colors[reset]}"
    prepare_output_files 
    run_whatweb_scan 
    find_subdomains_and_endpoints
    find_sqli_vulnerabilities
    run_xss_scan
    run_open_redirect_scan
    run_lfi_scan
    run_secretfinder_scan
    run_nikto_scan
    run_nuclei_scan
    output_summary
    echo -e "${colors[green]}Full Scan completed.${colors[reset]}"
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
