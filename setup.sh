#!/bin/bash

# Exit on any error
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting installation of required tools...${NC}"

# Update package list
echo "Updating package list..."
sudo apt-get update -y

# Install Python3 and pip if not already installed
echo "Installing Python3 and pip..."
sudo apt-get install -y python3 python3-pip

# Install requests Python package
echo "Installing Python package: requests..."
pip3 install requests

# Install nmap
echo "Installing nmap..."
sudo apt-get install -y nmap

# Install hydra
echo "Installing hydra..."
sudo apt-get install -y hydra

# Install ffuf
echo "Installing ffuf..."
# Check if ffuf is already installed
if ! command -v ffuf &> /dev/null; then
    # Download the latest ffuf binary (adjust version as needed)
    FFUF_VERSION="2.1.0"  # Check https://github.com/ffuf/ffuf/releases for the latest version
    wget "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -O ffuf.tar.gz
    tar -xzf ffuf.tar.gz ffuf
    sudo mv ffuf /usr/local/bin/
    rm ffuf.tar.gz
    echo "ffuf installed successfully."
else
    echo "ffuf is already installed."
fi

# Verify installations
echo -e "\n${GREEN}Verifying installations...${NC}"
for tool in python3 pip3 nmap hydra ffuf; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}$tool is installed: $(which $tool)${NC}"
    else
        echo -e "${RED}Error: $tool is not installed!${NC}"
        exit 1
    fi
done

# Check requests installation
if python3 -c "import requests" &> /dev/null; then
    echo -e "${GREEN}Python requests module is installed.${NC}"
else
    echo -e "${RED}Error: Python requests module failed to install!${NC}"
    exit 1
fi

echo -e "${GREEN}All tools installed successfully!${NC}"
