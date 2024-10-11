#!/bin/bash
# Ansi color code variables
red="\e[0;91m"
blue="\e[0;94m"
yellow="\e[0;33m"
green="\e[0;92m"
cyan="\e[0;36m"
uline="\e[0;35m"
reset="\e[0m"

printf "\n${yellow}Welcome to Aung Recon main script
#              ╭━━━╮╱╱╱╱╱╱╱╱╱╭━━━╮
#              ┃╭━╮┃╱╱╱╱╱╱╱╱╱┃╭━╮┃
#              ┃┃╱┃┣╮╭┳━╮╭━━╮┃╰━╯┣━━┳━━┳━━┳━╮
#              ┃╰━╯┃┃┃┃╭╮┫╭╮┃┃╭╮╭┫┃━┫╭━┫╭╮┃╭╮╮
#              ┃╭━╮┃╰╯┃┃┃┃╰╯┃┃┃┃╰┫┃━┫╰━┫╰╯┃┃┃┃
#              ╰╯╱╰┻━━┻╯╰┻━╮┃╰╯╰━┻━━┻━━┻━━┻╯╰╯
#              ╱╱╱╱╱╱╱╱╱╱╭━╯┃
#              ╱╱╱╱╱╱╱╱╱╱╰━━╯  aungsanoo.com${reset}\n"


printf "\n${yellow}###############################${reset}\n"
V_MY_PATH=$HOME
# Ask the user for the website URL or domain
read -p "[+]Enter the website domain:" website_input

# Normalize the input: Add "https://" if the input is just a domain without protocol
if [[ ! $website_input =~ ^https?:// ]]; then
    website_url="https://$website_input"
else
    website_url="$website_input"
fi

# Inform the user of the normalized URL being used
echo -e "${blue}[+]Normalized URL being used${reset}: $website_url"
# Create an output directory if it doesn't exist
output_dir="output"
mkdir -p "$output_dir"
printf "${uline}#######################################################################${reset}\n"
#Sundomain
echo -e "${yellow}\e[5m[+]Findimg Subdomain......${reset}"
printf "${uline}#######################################################################${reset}\n"
subfinder -d $website_input -all -recursive > "sub.txt" 
printf "${uline}#######################################################################${reset}\n"
echo -e "${yellow}\e[5m[+] Filtering Alive Sundomains....${reset}"
printf "${uline}#######################################################################${reset}\n"
#And then we gona check which subdomain are alive using https tool
cat "sub.txt" | httpx -v > "alivesub.txt"
printf "${uline}#######################################################################${reset}\n"
#takeover
echo -e "${yellow}\e[5m[+] check subdomain takeover....${reset}"
printf "${uline}#######################################################################${reset}\n"
subzy run --targets "sub.txt"
printf "${uline}#######################################################################${reset}\n"
# SQLi
echo -e "${yellow}\e[5m[+]Finding SQLI vulnerability....${reset}"
printf "${uline}#######################################################################${reset}\n"
katana -list alivesub.txt -d 5 | grep '=' | urldedupe | anew allurls.txt
#Remove FUZZ and save as final.txt
cat allurls.txt | sed 's/=.*/=/' > final.txt
mv final.txt $HOME/aungrecon/output/final.txt
cd $HOME/aungrecon/bsqli
python3 main.py -l $HOME/aungrecon/output/final.txt -p payloads/xor.txt -t 5
cp output.txt $HOME/aungrecon/output/sqli_vul.txt
printf "${uline}#######################################################################${reset}\n"

echo -e "${yellow}\e[5m[+] Vulnerability: Multiples vulnerabilities....${reset}"
echo -e "${yellow}\e[5mRunning multiple templates to discover vulnerabilities....${reset}"
printf "${uline}#######################################################################${reset}\n"
nuclei -l $HOME/aungrecon/alivesub.txt -t $HOME/aungrecon/priv8-Nuclei -severity low,medium,high,critical  -o "$HOME/aungrecon/output/mutiple_vulnerabilities.txt"
printf "${uline}#######################################################################${reset}\n"
# XSS
echo -e "${yellow}\e[5m[+]Finding XSS vulnerability....${reset}"
printf "${uline}#######################################################################${reset}\n"
cd $HOME/aungrecon/xss_vibes
python3 main.py -f $HOME/aungrecon/output/final.txt -t 7 -o $HOME/aungrecon/output/xss_vul.txt.txt
printf "${uline}#######################################################################${reset}\n"

#OprnRedirect
echo -e "${yellow}\e[5m[+] Open Redirect Testing ....${reset}"
printf "${uline}#######################################################################${reset}\n"

cat $HOME/aungrecon/allurls.txt |  openredirex -p $HOME/aungrecon/or.txt -k "FUZZ" -c 30 > $HOME/aungrecon/open_redirect_vul.txt

# LFI
printf "${uline}#######################################################################${reset}\n"
echo -e "${yellow}\e[5m[+]Finding LFI vulnerability....${reset}"
printf "${uline}#######################################################################${reset}\n"
cd ..
echo $website_input | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w lfi.txt -c -mr "root:x:0:" -v > $HOME/aungrecon/output/lfi_vul.txt
printf "${uline}#######################################################################${reset}\n"
echo -e "${yellow}\e[5m[+] Remove the intermediate output files ....${reset}"
printf "${uline}#######################################################################${reset}\n"
mv $HOME/aungrecon/open_redirect_vul.txt $HOME/aungrecon/output/open_redirect_vul.txt
rm sub.txt alivesub.txt allurls.txt
cd bsqli
rm *.txt
cd ..
cd output
rm final.txt

printf "${uline}#######################################################################${reset}\n"
# Notify the user that all tasks are complete
echo -e "${yellow}\e[5mFiltered URLs have been saved to the respective output files in the 'output' directory:${reset}"
echo -e "${cyan}\e[5m- XSS: $output_dir/xss_vul.txt${reset}"
echo -e "${cyan}\e[5m- Open Redirect: $output_dir/open_redirect_vul.txt${reset}"
echo -e "${cyan}\e[5m- LFI: $output_dir/lfi_vul.txt${reset}"
echo -e "${cyan}\e[5m- SQLi: $output_dir/sqli_vul.txt${reset}"
echo -e "${cyan}\e[5m- SQLi: $output_dir/mutiple_vulnerabilities.txt${reset}"
printf "${uline}#######################################################################${reset}\n"
