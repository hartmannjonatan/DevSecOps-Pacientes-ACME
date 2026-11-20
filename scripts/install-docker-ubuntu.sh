#!/usr/bin/env bash
set -euo pipefail
# https://docs.docker.com/engine/install/ubuntu/
source /etc/os-release
[[ "$ID" == ubuntu ]] || { echo 'Este instalador requer Ubuntu.' >&2; exit 1; }
command -v docker >/dev/null && { docker version; docker compose version; exit; }
sudo apt-get update
sudo apt-get install -y ca-certificates curl util-linux-extra
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
printf 'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' "$VERSION_CODENAME" "$(dpkg --print-architecture)" | sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
sudo docker run --rm hello-world
# O grupo docker equivale a acesso administrativo; não altera grupos automaticamente.
