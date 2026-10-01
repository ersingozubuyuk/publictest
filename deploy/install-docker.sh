#!/usr/bin/env bash
# Docker Engine + Compose plugin kurulumu.
# Desteklenen: Ubuntu, Debian, RHEL, Rocky, AlmaLinux, CentOS Stream, Oracle Linux, SLES, openSUSE
# Kullanım:  sudo bash deploy/install-docker.sh
set -euo pipefail

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'HATA: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "root olarak çalıştırın:  sudo bash $0"
[ -r /etc/os-release ] || die "/etc/os-release bulunamadı, dağıtım tespit edilemedi"
. /etc/os-release
ARCH="$(uname -m)"
log "Dağıtım: ${PRETTY_NAME:-$ID} ($ARCH)"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  log "Docker ve Compose zaten kurulu:"
  docker --version; docker compose version
  exit 0
fi

install_compose_plugin() {
  # Dağıtım paketi Compose v2 eklentisini sağlamıyorsa resmi binary'yi kur.
  docker compose version >/dev/null 2>&1 && return 0
  log "Docker Compose eklentisi GitHub'dan kuruluyor"
  local dir=/usr/local/lib/docker/cli-plugins
  mkdir -p "$dir"
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${ARCH}" \
    -o "$dir/docker-compose"
  chmod +x "$dir/docker-compose"
}

case "$ID" in
  ubuntu|debian)
    log "Docker resmi APT deposu ekleniyor"
    apt-get update -y
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ;;

  rhel|rocky|almalinux|centos|ol)
    log "Docker resmi DNF deposu ekleniyor"
    repo=centos; [ "$ID" = "rhel" ] && repo=rhel
    dnf -y install dnf-plugins-core curl
    dnf config-manager --add-repo "https://download.docker.com/linux/${repo}/docker-ce.repo"
    # RHEL ailesinde podman/buildah çakışabilir
    dnf -y remove podman-docker buildah 2>/dev/null || true
    dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ;;

  sles|sles_sap)
    log "SLES Containers Module etkinleştiriliyor"
    SUSEConnect -p "sle-module-containers/${VERSION_ID}/${ARCH}" \
      || die "Containers Module etkinleştirilemedi (SUSEConnect kaydını kontrol edin)"
    zypper --non-interactive install docker
    install_compose_plugin
    ;;

  opensuse-leap|opensuse-tumbleweed)
    zypper --non-interactive install docker
    zypper --non-interactive install docker-compose || true
    install_compose_plugin
    ;;

  *)
    die "Desteklenmeyen dağıtım: $ID. Bkz. https://docs.docker.com/engine/install/"
    ;;
esac

log "Docker servisi başlatılıyor"
systemctl enable --now docker

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  usermod -aG docker "$SUDO_USER"
  log "$SUDO_USER docker grubuna eklendi (etkin olması için oturumu kapatıp açın)"
fi

log "Kurulum doğrulanıyor"
docker --version
docker compose version
docker info --format 'Docker çalışıyor: {{.ServerVersion}} / {{.OperatingSystem}}'
log "Tamamlandı"
