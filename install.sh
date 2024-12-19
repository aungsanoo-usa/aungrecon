#!/bin/bash

BOLD=$(tput bold)
YELLOW=$(tput setaf 3)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
NORMAL=$(tput sgr0)

# Determine the script directory dynamically
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_dir="$script_dir/tools"

printf "${BOLD}${YELLOW}##########################################################\n"
printf "##### Welcome to the AungRecon dependency installer #####\n"
printf "##########################################################\n\n${NORMAL}"

# Update package lists
sudo apt -y update

# Install required programming languages and essential packages
printf "${BOLD}${MAGENTA}Installing programming languages and essential packages\n${NORMAL}"
sudo apt install -y golang-go cmake jq whatweb ffuf nikto curl python3-pip unzip wget -y || echo "Error installing essential packages"

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
  rm -rf chromedriver-linux64.zip chromedriver-linux64 google-chrome-stable_current_amd64.deb
else
  echo "Failed to download ChromeDriver. Please check the provided URL or your network connection."
fi

# Create AungRecon directory if it doesn't exist
cd "$script_dir" || echo "Failed to change to script directory"

# Set up tools directory
mkdir -p "$tools_dir"

# Install Go-based tools
printf "${BOLD}${MAGENTA}Installing Go-based tools\n${NORMAL}"
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
  "github.com/damit5/gitdorks_go"
  "github.com/tomnomnom/unfurl"
  "github.com/trickest/enumerepo"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
)

go_bin_path=$(go env GOPATH)/bin

for tool in "${GO_TOOLS[@]}"; do
  tool_name=$(basename "$tool")
  printf "${CYAN}Installing $tool_name\n${NORMAL}"
  go install -v "$tool@latest" || echo "Failed to install Go tool: $tool_name"
  
  sudo cp "$go_bin_path/$tool_name" /usr/local/bin/ || echo "Failed to move $tool_name to /usr/local/bin"
done

# Install Python tools
printf "${CYAN}Installing Python-based tools (porch-pirate, emailfinder)\n${NORMAL}"
python3 -m pip install porch-pirate emailfinder metafinder selenium setuptools --break-system-packages || echo "Failed to install Python tools"

# Fix emailfinder banner issue
printf "${CYAN}Fixing emailfinder banner issue\n${NORMAL}"
EMAILFINDER_PATH=$(python3 -c "import emailfinder, os; print(os.path.dirname(emailfinder.__file__))")
if [[ -d "$EMAILFINDER_PATH" ]]; then
  sed -i 's/^\( *\)show_banner()/\1# show_banner()  # Disabled to prevent font issues/' "$EMAILFINDER_PATH/cli.py"
  echo "[+] Emailfinder banner issue fixed."
else
  echo "[!] Emailfinder module not found."
fi

# Clone repositories and install dependencies
printf "${BOLD}${MAGENTA}Cloning repositories and installing dependencies\n${NORMAL}"
declare -A REPOS=(
  ["paramspider"]="https://github.com/devanshbatham/paramspider"
  ["gFpattren"]="https://github.com/coffinxp/gFpattren.git"
  ["urldedupe"]="https://github.com/ameenmaali/urldedupe"
  ["priv8-Nuclei"]="https://github.com/aungsanoo-usa/priv8-Nuclei.git"
  ["bsqli"]="https://github.com/KKonaNN/bsqli.git"
  ["xss_scanner"]="https://github.com/aungsanoo-usa/xss_scanner.git"
  ["lfi_scanner"]="https://github.com/aungsanoo-usa/lfi_scanner.git"
  ["SecretFinder"]="https://github.com/m4ll0k/SecretFinder.git"
  ["SwaggerSpy"]="https://github.com/UndeadSec/SwaggerSpy.git"
  ["LeakSearch"]="https://github.com/JoelGMSec/LeakSearch.git"
  ["Spoofy"]="https://github.com/MattKeeley/Spoofy.git"
  ["dorks_hunter"]="https://github.com/six2dez/dorks_hunter"
  ["misconfig-mapper"]="https://github.com/intigriti/misconfig-mapper.git"
)

for repo in "${!REPOS[@]}"; do
    printf "${CYAN}Cloning $repo...${NORMAL}\n"
    git clone "${REPOS[$repo]}" "$tools_dir/$repo" || echo "${RED}Failed to clone $repo.${NORMAL}"
    cd "$tools_dir/$repo" || continue

    # Build Go tools if applicable
    if [[ -f go.mod ]]; then
        go build -o "$repo" || echo "${RED}Failed to build $repo.${NORMAL}"
        sudo mv "$repo" /usr/local/bin/
    fi

    # Install Python requirements if needed
    if [[ -f requirements.txt ]]; then
        pip3 install -r requirements.txt --break-system-packages || echo "${RED}Failed to install dependencies for $repo.${NORMAL}"
    fi
done
# Copy Gf patterns to the correct directory
# Fix GF Patterns
printf "${CYAN}Copying GF patterns...\n${NORMAL}"
if [[ -d "$tools_dir/gFpattren" ]]; then
    mkdir -p ~/.gf
    cp -r "$tools_dir/gFpattren"/* ~/.gf || echo "${RED}Failed to copy GF patterns.${NORMAL}"
else
    echo "${RED}GF patterns directory not found. Skipping.${NORMAL}"
fi
cd "$script_dir" || exit 1
# Clone Misconfig Mapper
printf "${CYAN}Installing Misconfig Mapper...\n${NORMAL}"
if [[ ! -d "$tools_dir/misconfig-mapper" ]]; then
    git clone https://github.com/intigriti/misconfig-mapper.git "$tools_dir/misconfig-mapper" || {
        echo "${RED}[!] Failed to clone Misconfig Mapper.${NORMAL}"
        exit 1
    }
else
    echo "${YELLOW}[!] Misconfig Mapper already exists. Skipping clone.${NORMAL}"
fi

# Build Misconfig Mapper
if [[ -d "$tools_dir/misconfig-mapper" ]]; then
    cd "$tools_dir/misconfig-mapper" || exit
    printf "${CYAN}[+] Building Misconfig Mapper binary...\n${NORMAL}"
    go build -o misconfig-mapper || echo "${RED}[!] Failed to build Misconfig Mapper binary.${NORMAL}"
    echo -e "${CYAN}[+] Updating Misconfig Mapper templates...${NORMAL}"
    ./misconfig-mapper -update-templates || echo "${RED}[!] Failed to update templates.${NORMAL}"
    cd "$script_dir" || exit
fi

# Install gitdorks_go
printf "${CYAN}Installing gitdorks_go...\n${NORMAL}"
if ! command -v gitdorks_go &>/dev/null; then
    go install -v github.com/damit5/gitdorks_go@latest || echo "${RED}[!] Failed to install gitdorks_go.${NORMAL}"
    sudo cp "$(go env GOPATH)/bin/gitdorks_go" /usr/local/bin/ || echo "${RED}[!] Failed to move gitdorks_go to /usr/local/bin.${NORMAL}"
else
    echo "${GREEN}[+] gitdorks_go is already installed.${NORMAL}"
fi

# Ensure dorks files exist
if [[ ! -d "$tools_dir/gitdorks_go/Dorks" ]]; then
    printf "${CYAN}Cloning Dorks repository for gitdorks_go...\n${NORMAL}"
    mkdir -p "$tools_dir/gitdorks_go/Dorks"
    wget -q https://raw.githubusercontent.com/damit5/gitdorks_go/refs/heads/d4m1ts/Dorks/smalldorks.txt -O "$tools_dir/gitdorks_go/Dorks/smalldorks.txt"
    wget -q https://raw.githubusercontent.com/damit5/gitdorks_go/refs/heads/d4m1ts/Dorks/medium_dorks.txt -O "$tools_dir/gitdorks_go/Dorks/medium_dorks.txt"
fi


# Set up paramspider
printf "${CYAN}Setting up paramspider\n${NORMAL}"
cd "$tools_dir/paramspider" || echo "Failed to change to paramspider directory"
pip3 install . --break-system-packages || echo "Failed to install paramspider"
sudo mv ~/.local/bin/paramspider /usr/local/bin || echo "Failed to move paramspider to /usr/local/bin"
cd .. || echo "Failed to return to aungrecon directory"

# Set up urldedupe
printf "${CYAN}Setting up urldedupe\n${NORMAL}"
cd $tools_dir/urldedupe || echo "Failed to change to urldedupe directory"
cmake CMakeLists.txt || echo "Failed to run CMake for urldedupe"
make || echo "Failed to compile urldedupe"
sudo mv $tools_dir/urldedupe/urldedupe /usr/local/bin || echo "Failed to move urldedupe to /usr/local/bin"
sudo mv $go_bin_path/dalfox /usr/local/bin
printf "${CYAN}Installing Python-based tools (uro, pystyle)\n${NORMAL}"
sudo pip3 install uro pystyle --break-system-packages || echo "Failed to install Python tools"
sudo mv ~/.local/bin/uro /usr/local/bin || echo "Failed to move uro to /usr/local/bin"


# Final message
printf "${BOLD}${YELLOW}Installation completed (with warnings, if any)!\n${NORMAL}"
