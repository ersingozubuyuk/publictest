# kernelassess

SUSE Linux Enterprise (özellikle IBM Power LPAR) filoları için **Kernel Security & Lifecycle Assessment** aracı.
Sunucuya bağlanmadan, yalnızca beyan edilen OS / SP / kernel sürümünden ve resmi SUSE verisinden analiz üretir.

## İlkeler

- **Rakamları kod üretir, LLM değil.** Advisory, CVE, CVSS, tarih ve skorların hepsi resmi kaynaktan deterministik olarak hesaplanır.
- **Uydurma yok.** Bulunamayan değerler `Unknown` / `Not Available` / `Not Verified` olarak gösterilir.
- **Gerçek veri dışarı çıkmaz.** Hostname'ler `HOST-0001` gibi takma adlarla değiştirilir, gerçek eşleşme yalnızca `out/private/masking-map.json` dosyasında yerel olarak tutulur.

## Kurulum ve kullanım

**Sunucuda Docker ile:** [deploy/KURULUM.md](deploy/KURULUM.md) — Docker kurulumu dahil adım adım.

**Test dashboard'u:** `http://SUNUCU:8080` — envanter CSV yükleme, filo tablosu, host detay (timeline, eksik CVE'ler, lifecycle, Not Verified listesi), JSON indirme. Basic auth ile korunur. Nihai müşteri raporu Faz 3'te gelecek.

**Lokal geliştirme:**

```bash
pip install -e ".[web,dev]"
kernelassess web                                     # http://127.0.0.1:8080
kernelassess fetch                                   # SUSE OVAL verisini indir/güncelle (~80 MB, koşullu GET)
kernelassess assess examples/inventory.csv -o out    # filoyu analiz et
kernelassess assess inv.csv -o out --offline --date 2026-10-01
pytest
```

Envanter CSV (`,` `;` veya TAB):

```
hostname,os,version,kernel,architecture,platform
LPAR001,SLES,15 SP6,6.4.0-150600.23.25-default,ppc64le,IBM Power
```

Çıktılar:

| Dosya | İçerik |
|---|---|
| `out/hosts/HOST-xxxx.json` | Host bazında tam analiz (maskeli) |
| `out/fleet-summary.json` | Filo özeti, tekil eksik CVE sayıları |
| `out/private/masking-map.json` | HOST-id → gerçek hostname (**paylaşmayın**) |

## Veri kaynakları

| Kaynak | Kullanım |
|---|---|
| SUSE OVAL patch feed (`ftp.suse.com/pub/projects/security/oval/`) | Advisory ID, tarih, severity, CVE, SUSE/NVD CVSS, düzeltilen kernel sürümü, değişiklik listesi |
| SUSE Product Lifecycle (`kernelassess/data/lifecycle.yaml`) | General / LTSS bitiş tarihleri (elle güncellenir, kaynak ve tarih dosyada) |

Severity önceliği: SUSE değerlendirmesi → NVD → CVSS bandı → `Unknown`.

## Bilinen sınırlamalar

- OVAL verisi mimari ayrımı yapmaz; CVE'nin ppc64le için geçerliliği `Not Verified` olarak işaretlenir.
- SUSE bazı CVE'leri advisory metninde tek tek açıklamaz; bunların özeti/component bilgisi `Not Available` olarak kalır (Faz 2: NVD ile zenginleştirme).
- LTSS aboneliği, firmware, HMC, VIOS, LPM bilgileri sunucu erişimi olmadan doğrulanamaz.

## Yol haritası

| Faz | Durum |
|---|---|
| 1. Veri katmanı: kernel parser, SUSE OVAL, lifecycle, CSV envanter, maskeleme, host JSON | ✅ |
| 2. Analiz motoru: skor formülleri (Health/Security/Lifecycle/Vendor/Currency/Confidence), NVD zenginleştirme | ⏳ |
| 3. HTML/PDF rapor şablonu (cover, gauge, KPI, timeline, risk matrix, QR) + filo dashboard'u | ⏳ |
| 4. LLM katmanı (Bulutistan LLMaaS, OpenAI uyumlu): executive summary, "What Changed", öneri metni + uydurma bekçisi | ⏳ |
| 5. IBM Power modülü genişletme | ⏳ |
| 6. Doğrulama: SUSE sitesiyle örneklem karşılaştırma, snapshot testleri | ⏳ |
