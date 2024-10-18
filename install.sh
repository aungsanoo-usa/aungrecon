#!/bin/bash

BOLD=$(tput bold)
YELLOW=$(tput setaf 3)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
NORMAL=$(tput sgr0)

printf "${BOLD}${YELLOW}##########################################################\n"
printf "##### Welcome to the AungRecon dependency installer #####\n"
printf "##########################################################\n\n${NORMAL}"

# Update package lists
sudo apt -y update

# Install required programming languages and essential packages
printf "${BOLD}${MAGENTA}Installing programming languages and essential packages\n${NORMAL}"
sudo apt install -y golang-go cmake whatweb ffuf sqlmap || echo "Error installing essential packages"

# Create AungRecon directory if it doesn't exist
cd $HOME || echo "Failed to change to home directory"
mkdir -p aungrecon
cd aungrecon || echo "Failed to change to aungrecon directory"

# Clone repositories and install dependencies
printf "${BOLD}${MAGENTA}Cloning repositories and installing dependencies\n${NORMAL}"
declare -A REPOS=(
  ["paramspider"]="https://github.com/devanshbatham/paramspider"
  ["openredirex"]="https://github.com/devanshbatham/openredirex"
  ["Gf-Patterns"]="https://github.com/1ndianl33t/Gf-Patterns"
  ["urldedupe"]="https://github.com/ameenmaali/urldedupe"
  ["priv8-Nuclei"]="https://github.com/aungsanoo-usa/priv8-Nuclei.git"
)

for repo in "${!REPOS[@]}"; do
  printf "${CYAN}Cloning ${repo}\n${NORMAL}"
  git clone "${REPOS[$repo]}" || echo "Failed to clone ${repo}"
  cd "$(basename "$repo")" || echo "Failed to change directory to ${repo}"
  
  if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt --break-system-packages || echo "Failed to install Python dependencies for ${repo}"
  fi
  
  cd .. || echo "Failed to return to aungrecon directory"
done

# Copy Gf patterns to the correct directory
mkdir -p ~/.gf
cp -r Gf-Patterns/* ~/.gf || echo "Failed to copy GF patterns"

# Install Go-based tools
printf "${BOLD}${MAGENTA}Installing GO tools\n${NORMAL}"
declare -a GO_TOOLS=(
  "github.com/hahwul/dalfox/v2"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx"
  "github.com/lc/gau"
  "github.com/tomnomnom/gf"
  "github.com/tomnomnom/qsreplace"
  "github.com/PentestPad/subzy"
  "github.com/tomnomnom/anew"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
)

for tool in "${GO_TOOLS[@]}"; do
  tool_name=$(basename "$tool")
  printf "${CYAN}Installing $tool_name\n${NORMAL}"
  go install "$tool@latest" || echo "Failed to install Go tool: $tool_name"
  
  # Correct binary names for each tool
  if [[ "$tool_name" == "dalfox" ]]; then
    sudo cp "$HOME/go/bin/dalfox" /usr/local/bin/ || echo "Failed to move dalfox to /usr/local/bin"
  elif [[ "$tool_name" == "subfinder" ]]; then
    sudo cp "$HOME/go/bin/subfinder" /usr/local/bin/ || echo "Failed to move subfinder to /usr/local/bin"
  elif [[ "$tool_name" == "httpx" ]]; then
    sudo cp "$HOME/go/bin/httpx" /usr/local/bin/ || echo "Failed to move httpx to /usr/local/bin"
  elif [[ "$tool_name" == "gau" ]]; then
    sudo cp "$HOME/go/bin/gau" /usr/local/bin/ || echo "Failed to move gau to /usr/local/bin"
  elif [[ "$tool_name" == "gf" ]]; then
    sudo cp "$HOME/go/bin/gf" /usr/local/bin/ || echo "Failed to move gf to /usr/local/bin"
  elif [[ "$tool_name" == "qsreplace" ]]; then
    sudo cp "$HOME/go/bin/qsreplace" /usr/local/bin/ || echo "Failed to move qsreplace to /usr/local/bin"
  elif [[ "$tool_name" == "subzy" ]]; then
    sudo cp "$HOME/go/bin/subzy" /usr/local/bin/ || echo "Failed to move subzy to /usr/local/bin"
  elif [[ "$tool_name" == "anew" ]]; then
    sudo cp "$HOME/go/bin/anew" /usr/local/bin/ || echo "Failed to move anew to /usr/local/bin"
  elif [[ "$tool_name" == "nuclei" ]]; then
    sudo cp "$HOME/go/bin/nuclei" /usr/local/bin/ || echo "Failed to move nuclei to /usr/local/bin"
  fi
done

# Set up openredirex
printf "${CYAN}Setting up openredirex\n${NORMAL}"
cd $HOME/aungrecon/openredirex || echo "Failed to change to openredirex directory"
chmod +x setup.sh
sudo bash setup.sh || echo "Failed to set up openredirex"
cd .. || echo "Failed to return to aungrecon directory"

# Set up paramspider
printf "${CYAN}Setting up paramspider\n${NORMAL}"
cd $HOME/aungrecon/paramspider || echo "Failed to change to paramspider directory"
pip3 install . --break-system-packages || echo "Failed to install paramspider"
cd .. || echo "Failed to return to aungrecon directory"

# Install Python tools
printf "${CYAN}Installing Python-based tools (uro, pystyle)\n${NORMAL}"
sudo pip3 install uro pystyle --break-system-packages || echo "Failed to install Python tools"
sudo mv ~/.local/bin/uro /usr/local/bin || echo "Failed to move uro to /usr/local/bin"

# Set up urldedupe
printf "${CYAN}Setting up urldedupe\n${NORMAL}"
cd $HOME/aungrecon/urldedupe || echo "Failed to change to urldedupe directory"
cmake CMakeLists.txt || echo "Failed to run CMake for urldedupe"
make || echo "Failed to compile urldedupe"
sudo mv $HOME/aungrecon/urldedupe/urldedupe /usr/local/bin || echo "Failed to move urldedupe to /usr/local/bin"

# Final message
printf "${BOLD}${YELLOW}Installation completed (with warnings, if any)!\n${NORMAL}"
