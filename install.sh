#!/bin/bash

BOLD=$(tput bold)
YELLOW=$(tput setaf 3)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
NORMAL=$(tput sgr0)

# Determine the script directory dynamically
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf "${BOLD}${YELLOW}##########################################################\n"
printf "##### Welcome to the AungRecon dependency installer #####\n"
printf "##########################################################\n\n${NORMAL}"

# Update package lists
sudo apt -y update

# Install required programming languages and essential packages
printf "${BOLD}${MAGENTA}Installing programming languages and essential packages\n${NORMAL}"
sudo apt install -y golang-go cmake whatweb ffuf nikto || echo "Error installing essential packages"

# Install Selenium and ChromeDriver dependencies
printf "${CYAN}Installing Selenium and ChromeDriver dependencies\n${NORMAL}"
sudo apt install -y python3-pip unzip wget || echo "Error installing Python and other dependencies"

# Install Selenium for Python
pip3 install selenium setuptools --break-system-packages || echo "Failed to install Selenium"

# Install Google Chrome
printf "${CYAN}Installing Google Chrome\n${NORMAL}"
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb || echo "Failed to install Google Chrome"
sudo apt-get install -f -y  # Fix any dependencies

# Download and install the specified ChromeDriver version
printf "${CYAN}Installing ChromeDriver version 128.0.6613.119\n${NORMAL}"
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip -O chromedriver-linux64.zip
if [[ $? -eq 0 ]]; then
  unzip chromedriver-linux64.zip
  sudo mv chromedriver-linux64/chromedriver /usr/local/bin/ || echo "Failed to move ChromeDriver to /usr/local/bin"
  rm -rf chromedriver-linux64.zip chromedriver-linux64
else
  echo "Failed to download ChromeDriver. Please check the provided URL or your network connection."
fi

# Create AungRecon directory if it doesn't exist
cd "$script_dir" || echo "Failed to change to script directory"

# Clone repositories and install dependencies
printf "${BOLD}${MAGENTA}Cloning repositories and installing dependencies\n${NORMAL}"
declare -A REPOS=(
  ["paramspider"]="https://github.com/devanshbatham/paramspider"
  ["gFpattren"]="https://github.com/coffinxp/gFpattren.git"
  ["urldedupe"]="https://github.com/ameenmaali/urldedupe"
  ["priv8-Nuclei"]="https://github.com/aungsanoo-usa/priv8-Nuclei.git"
  ["bsqli"]="https://github.com/aungsanoo-usa/bsqli.git"
  ["xss_scanner"]="https://github.com/aungsanoo-usa/xss_scanner.git"
  ["lfi_scanner"]="https://github.com/aungsanoo-usa/lfi_scanner.git"
  ["SecretFinder"]="https://github.com/m4ll0k/SecretFinder.git"
)

for repo in "${!REPOS[@]}"; do
  printf "${CYAN}Cloning ${repo}\n${NORMAL}"
  git clone "${REPOS[$repo]}" || echo "Failed to clone ${repo}"
  cd "$(basename "$repo")" || echo "Failed to change directory to ${repo}"
  
  if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt --break-system-packages || echo "Failed to install Python dependencies for ${repo}"
  fi
  
  cd "$script_dir" || echo "Failed to return to aungrecon directory"
done

# Copy Gf patterns to the correct directory
mkdir -p ~/.gf
cp -r gFpattren/* ~/.gf || echo "Failed to copy GF patterns"

# Install Go-based tools
printf "${BOLD}${MAGENTA}Installing GO tools\n${NORMAL}"
declare -a GO_TOOLS=(
  "github.com/hahwul/dalfox/v2"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx"
  "github.com/lc/gau"
  "github.com/tomnomnom/gf"
  "github.com/KathanP19/Gxss"
  "github.com/Emoe/kxss"
  "github.com/tomnomnom/qsreplace"
  "github.com/PentestPad/subzy"
  "github.com/tomnomnom/anew"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  "github.com/projectdiscovery/katana/cmd/katana"
)

go_bin_path=$(go env GOPATH)/bin

for tool in "${GO_TOOLS[@]}"; do
  tool_name=$(basename "$tool")
  printf "${CYAN}Installing $tool_name\n${NORMAL}"
  go install "$tool@latest" || echo "Failed to install Go tool: $tool_name"
  
  sudo cp "$go_bin_path/$tool_name" /usr/local/bin/ || echo "Failed to move $tool_name to /usr/local/bin"
done

# Set up paramspider
printf "${CYAN}Setting up paramspider\n${NORMAL}"
cd $script_dir/paramspider || echo "Failed to change to paramspider directory"
pip3 install . --break-system-packages || echo "Failed to install paramspider"
sudo mv ~/.local/bin/paramspider /usr/local/bin || echo "Failed to move paramspider to /usr/local/bin"
cd .. || echo "Failed to return to aungrecon directory"

# Install Python tools
printf "${CYAN}Installing Python-based tools (uro, pystyle)\n${NORMAL}"
sudo pip3 install uro pystyle --break-system-packages || echo "Failed to install Python tools"
sudo mv ~/.local/bin/uro /usr/local/bin || echo "Failed to move uro to /usr/local/bin"

# Set up urldedupe
printf "${CYAN}Setting up urldedupe\n${NORMAL}"
cd $script_dir/urldedupe || echo "Failed to change to urldedupe directory"
cmake CMakeLists.txt || echo "Failed to run CMake for urldedupe"
make || echo "Failed to compile urldedupe"
sudo mv $script_dir/urldedupe/urldedupe /usr/local/bin || echo "Failed to move urldedupe to /usr/local/bin"
sudo mv $go_bin_path/dalfox /usr/local/bin
# Final message
printf "${BOLD}${YELLOW}Installation completed (with warnings, if any)!\n${NORMAL}"
