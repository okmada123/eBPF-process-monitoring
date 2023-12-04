#!/bin/bash
# This script MIGHT help you install everything necessary to run the program.
# It was tested on Debian 12 (6.1.0-12-amd64) https://app.vagrantup.com/generic/boxes/debian12

echo "Installing Docker, pip3 and BCC..."

# Docker repo
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update && sudo apt upgrade -y

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
sudo apt install -y python3-pip

# Create .env files
echo "Creating .env and web-stack/backend/.env files with default content..."
touch .env
touch web-stack/backend/.env

echo 'API_HOST="localhost"' >> .env
echo 'API_PORT="8080"' >> .env
echo 'API_PROXY="/api"' >> .env

echo 'MONGO_HOST="mongo.local"' >> web-stack/backend/.env
echo 'MONGO_PORT=27017' >> web-stack/backend/.env
echo 'DB_NAME="monitoringDb"' >> web-stack/backend/.env

# Python
echo "Installing python requirements..."
pip3 install python-dotenv --break-system-packages

echo "DONE!!!"