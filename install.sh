#!/bin/bash

BOLD=$(tput bold)
YELLOW=$(tput setaf 3)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
NORMAL=$(tput sgr0)

printf "${BOLD}${YELLOW}##########################################################\n"
printf "##### Welcome to the AungRecon dependency installer #####\n"
printf "##########################################################\n\n${NORMAL}"

sudo apt-get -y update

printf "${BOLD}${MAGENTA}Installing programming languages and essential packages\n${NORMAL}"
sudo apt install -y golang-go

printf "${BOLD}${MAGENTA}Cloning repositories and installing dependencies\n${NORMAL}"
cd $HOME/aungrecon

declare -A REPOS=(
  ["xss_vibes"]="https://github.com/faiyazahmad07/xss_vibes.git"
  ["paramspider"]="https://github.com/devanshbatham/paramspider"
  ["bsqli"]="https://github.com/KKonaNN/bsqli.git"
  ["openredirex"]="https://github.com/devanshbatham/openredirex"
  ["Gf-Patterns"]="https://github.com/1ndianl33t/Gf-Patterns"
)

for repo in "${!REPOS[@]}"; do
  printf "${CYAN}Cloning ${repo}\n${NORMAL}"
  git clone "${REPOS[$repo]}"
  cd "$repo"
  if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt --break-system-packages
  fi
  cd ..
 
done

mkdir -p ~/.gf
cp -r Gf-Patterns/* ~/.gf

printf "${BOLD}${MAGENTA}Installing GO tools\n${NORMAL}"
declare -a GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx"
  "github.com/lc/gau"
  "github.com/tomnomnom/gf"
  "github.com/tomnomnom/qsreplace"
  "github.com/PentestPad/subzy"
)

for tool in "${GO_TOOLS[@]}"; do
  printf "${CYAN}Installing $(basename $tool)\n${NORMAL}"
  go install "$tool@latest"
  sudo cp "$HOME/go/bin/$(basename $tool)" /usr/local/bin/
done

printf "${CYAN}Installing ffuf\n${NORMAL}"
sudo apt install ffuf

printf "${CYAN}openredirex\n${NORMAL}"
cd $HOME/aungrecon/openredirex
chmod +x setup.sh
sudo bash setup.sh
cd ..

printf "${CYAN}Paramspider\n${NORMAL}"
cd $HOME/aungrecon/paramspider
pip install .
sudo mv ~/.local/bin/paramspider /usr/local/bin
cd ..

printf "${CYAN}Installing uro\n${NORMAL}"
sudo pip3 install uro

printf "${CYAN}Installing pystyle\n${NORMAL}"
sudo pip3 install pystyle

printf "${BOLD}${YELLOW}Installation completed successfully!\n${NORMAL}"
