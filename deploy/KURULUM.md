# Sanal sunucuya Docker ile kurulum

Gereksinimler: Linux sanal sunucu (Ubuntu/Debian, RHEL/Rocky/Alma, SLES veya openSUSE), `sudo` yetkisi, internete
(`ftp.suse.com`, `download.docker.com`, Docker Hub) erişim, en az 1 GB boş RAM ve 2 GB disk.

## 1. Projeyi sunucuya kopyala (Windows'tan)

PowerShell:

```powershell
cd C:\Projeler
tar --exclude=ersin/cache --exclude=ersin/out --exclude=ersin/runs --exclude=*.egg-info -czf kernelassess.tgz ersin
scp kernelassess.tgz KULLANICI@SUNUCU_IP:/tmp/
```

Sunucuda:

```bash
sudo mkdir -p /opt/kernelassess
sudo tar -xzf /tmp/kernelassess.tgz -C /opt/kernelassess --strip-components=1
sudo chown -R "$USER": /opt/kernelassess
cd /opt/kernelassess
```

## 2. Docker'ı kur

```bash
sudo bash deploy/install-docker.sh
```

Betik dağıtımı otomatik tespit eder, Docker'ın resmi deposunu ekler, Docker Engine + Compose eklentisini kurar,
servisi başlatır ve kullanıcınızı `docker` grubuna ekler. Bitince **oturumu kapatıp yeniden açın**
(grup üyeliğinin etkinleşmesi için), ardından kontrol edin:

```bash
docker run --rm hello-world
```

> SLES'te betik `SUSEConnect` ile *Containers Module*'ü etkinleştirir; sunucunun SCC/RMT kaydı olmalıdır.

## 3. Ayarları yap ve başlat

```bash
cp .env.example .env
nano .env                # DASHBOARD_PASSWORD'u mutlaka değiştirin
docker compose up -d --build
docker compose logs -f   # "Application startup complete" görünce Ctrl+C
```

İlk açılışta SUSE verisi indirilir ve indekslenir (~80 MB, 1-2 dk). Durumu kontrol etmek için:

```bash
curl -s localhost:8080/healthz      # "status":"ready" olmalı
```

## 4. Dashboard'a eriş

Tarayıcı: `http://SUNUCU_IP:8080` → kullanıcı `admin`, şifre `.env` içindeki değer.

Port kapalıysa:

```bash
sudo ufw allow 8080/tcp                                         # Ubuntu
sudo firewall-cmd --permanent --add-port=8080/tcp && sudo firewall-cmd --reload   # RHEL/SLES
```

Daha güvenli seçenek: portu dışarı açmayın, `docker-compose.yml` içinde `"127.0.0.1:8080:8080"` yapın ve
kendi bilgisayarınızdan SSH tüneli kullanın: `ssh -L 8080:localhost:8080 KULLANICI@SUNUCU_IP` → `http://localhost:8080`.

## Günlük kullanım

| İş | Komut |
|---|---|
| Durdur / başlat | `docker compose stop` / `docker compose start` |
| Logları izle | `docker compose logs -f` |
| Kod güncellemesi sonrası | yeni paketi aynı klasöre aç → `docker compose up -d --build` |
| SUSE verisini elle güncelle | Dashboard'daki **Şimdi güncelle** butonu (otomatik: her 24 saatte bir) |
| CLI ile analiz | `docker compose cp envanter.csv kernelassess:/data/envanter.csv` → `docker compose exec kernelassess kernelassess assess /data/envanter.csv -o /data/out` |
| Sonuçları dışarı al | `docker compose cp kernelassess:/data/runs ./runs-yedek` |

Veriler (`cache/`, `runs/`) `kernelassess-data` isimli Docker volume'ünde durur; konteyner silinse de kaybolmaz.
`runs/*/private/` klasörleri gerçek hostname'leri içerir; yedeklerken buna dikkat edin.

## Sorun giderme

- **`status":"error"` / indirme başarısız**: Sunucudan `curl -I https://ftp.suse.com` çalışıyor mu? Proxy varsa `.env`'de `HTTPS_PROXY` tanımlayıp `docker compose up -d`.
- **401 hatası**: `.env`'deki kullanıcı/şifreyi kullanın; değiştirdiyseniz `docker compose up -d` ile yeniden başlatın.
- **Bellek**: OVAL indekslemesi en fazla ~200 MB RAM kullanır (ölçülen tepe: 165 MB); `mem_limit` 1 GB olarak ayarlıdır.
