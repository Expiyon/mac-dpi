# mac-dpi — macOS için yerel DPI atlatma proxy'si

**Türkçe** · [English](README.md)

`SpoofDPI` / `GoodbyeDPI` mantığında, **kurulum gerektirmeyen** (saf Python, yalnız
standart kütüphane) bir anti-sansür aracı. macOS 11+ ve sistem `python3`'ü yeter.

| Sansür yöntemi | Bu aracın karşılığı |
|---|---|
| **SNI filtreleme** — DPI, TLS ClientHello'daki alan adını okuyup RST atar | ClientHello, SNI'nin ortasından hem **TCP segmentine** hem de **ayrı TLS kayıtlarına** bölünür (`record-frag`) |
| **HTTP `Host:` filtreleme** | Düz HTTP isteği `Host:` satırından bölünür |
| **DNS zehirleme / ISP DNS sansürü** | Alan adları **DNS-over-HTTPS** ile, DoH bağlantısının kendisi de parçalı olarak çözülür |
| **TLS alert / sahte sertifika enjeksiyonu** | Tespit edilir, başka yöntem denenir |

---

## 1. En hızlı yol — çift tıkla

`dpi` klasöründe **`dpi.command`**'a çift tıkla → Terminal açılır, proxy çalışır,
macOS sistem proxy'si otomatik `127.0.0.1:8080`'e ayarlanır. Pencereyi kapat / Ctrl+C
→ **sistem ayarların otomatik eski haline döner.**

İlk açılışta "geliştirici doğrulanamadı" → dosyaya **sağ tık → Aç** (bir kez).
`DPI.app` da aynı işi yapar; `dpi.command` ile aynı klasörde tut.

> `set-proxy` bazı macOS sürümlerinde yönetici parolası ister. Hata verirse bir kez
> `sudo python3 dpi.py set-proxy` çalıştır; sonrası sorunsuz.

---

## 2. Bir site hâlâ açılmıyorsa → `diag`

```bash
python3 dpi.py diag acilmayan-site.com
```

Sana tam olarak **neyin** engellediğini ve **hangi stratejinin geçtiğini** söyler:

- DNS'i kim kirletiyor (sistem DNS vs DoH farkı)
- IP seviyesinde mi engelli (o zaman userspace çözemez → VPN)
- SNI tabanlı DPI mi (parçalama ile geçilir)
- Hangi parçalama stratejileri **GEÇER** → onu `--strategy` ile sabitle ya da `auto`
  zaten bulur ve `~/.config/dpi/learned.json`'a yazar.

Örnek çıktı (temsili):

```
[DNS] sistem cozumleyici : 198.51.100.10          <- ISP blok-sayfası IP'si
[DNS] DoH (1.1.1.1 vb.)   : 203.0.113.42 ...       <- gerçek IP
[TLS] parcalama YOK ...   : ClientHello sonrasi RST -> SNI TABANLI DPI ENGELI
   --   sni-mid       reset
   GECER record-frag  ok  HTTP/1.1 200 OK
  SONUC: GECEN strateji: record-frag  ->  python3 dpi.py --strategy record-frag
```

---

## 3. Terminal komutları

```bash
python3 dpi.py                 # dinle + sistem proxy'sini ayarla (çıkışta geri al)
python3 dpi.py --no-set-proxy  # sadece proxy; sisteme dokunma (curl -x ... ile kullan)
python3 dpi.py --strategy record-frag   # tek strateji sabitle
python3 dpi.py diag site.com   # tanı
python3 dpi.py restore         # sistem proxy'sini elle geri yükle (kurtarma)
python3 dpi.py test            # kendi kendine test
python3 dpi.py strategies      # strateji listesi
```

Her açılışta arka planda:

```bash
./install-service.sh     # LaunchAgent: girişte başlar, sistem proxy'sini ayarlar
./uninstall-service.sh   # kaldırır + geri yükler
```

---

## Seçenekler

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `--listen ADRES` | `127.0.0.1:8080` | Dinlenecek adres/port |
| `--strategy AD` | `auto` | `auto` = uyarlanabilir. Sabit: `record-frag`, `record-tcp`, `record-frag-3`, `sni-mid`, `split-2`, `split-3`, `multi`, `oob-mid`, `oob`, `sni-1`, `byte-1`, `split-4`, `none` |
| `--delay-ms N` | `0` | Parçalar arası ek gecikme (ms). İnatçı DPI'da `25`–`40` dene (taban ~4 ms zaten var) |
| `--max-attempts N` | `8` | `auto` modda denenecek strateji sayısı |
| `--probe-timeout SN` | `2.5` | Bir stratejinin "geçti mi" bekleme süresi |
| `--max-conns N` | `512` | Eş zamanlı bağlantı sınırı |
| `--no-set-proxy` | — | macOS sistem proxy'sine dokunma |
| `--service AD` | otomatik | Sistem proxy için ağ servisi (`Wi-Fi`, …) |
| `--no-doh` | — | DoH kapalı, sistem DNS'i (dikkat: TR'de genelde zehirli) |
| `--doh-url URL` | Cloudflare + Google | DoH ucu, birden çok kez verilebilir (JSON API) |
| `--doh-strategy AD` | `sni-mid` | DoH bağlantısı için parçalama stratejisi |
| `--test-host AD` | `www.wikipedia.org` | Kendi testi / referans alan adı |
| `--fresh` | — | Öğrenilmiş stratejileri yok say |
| `-v` / `-q` | — | Ayrıntılı / sessiz log |

---

## Uyarlanabilir motor

`auto` sırası: `record-frag → record-tcp → record-frag-3 → sni-mid → split-2 →
multi → oob-mid → byte-1 → sni-1 → none`. TLS **kayıt** parçalaması modern SNI
DPI'sini (TR, RU) en çok geçiren yöntem olduğu için başta.

Bir alan adına bağlanırken: öğrenilmiş strateji varsa önce o; yoksa sıradaki
denenir. ClientHello gönderilir, geçerli **ServerHello** gelirse başarı; RST /
kapanma / TLS-alert gelirse **bağlantı kapatılmadan** taze soket üzerinde sıradaki
strateji denenir (tarayıcı fark etmez). İşe yarayan diske yazılır → sonraki
seferler anında.

Parçalar arasında en az ~4 ms bekleme var — TCP segmentlerinin gerçekten ayrılıp
DPI tarafından yeniden birleştirilememesini garanti eder.

---

## Güvenlik / kurtarma

- Sistem proxy'si açılmadan önceki tam durum `~/.config/dpi/proxy-backup.json`'a
  yazılır; çıkışta (Ctrl+C, pencere kapatma, `kill`) aynen geri yüklenir.
- Program çökerse: sonraki çalışmada otomatik geri yüklenir; ya da
  `python3 dpi.py restore` (gerekirse `sudo`).
- Önceki durum zaten bir yerel proxy'ye (`127.x`) işaret ediyorsa yedeğe "kapalı"
  yazılır — ölü bir yerel proxy internetini kesmesin.

---

## Sınırlar (dürüstçe)

- **IP seviyesinde engel** (sitenin IP'si null-route): hiçbir userspace yöntem
  çözemez. `diag` bunu "SYN'e cevap YOK" diye söyler → VPN / Tor / Xray gerekir.
- **DoH da engelliyse** ve DNS zehirliyse: `--doh-url https://8.8.8.8/resolve`
  dene; olmazsa VPN.
- **Sahte paket / düşük TTL / TCP-desync** (GoodbyeDPI, zapret): ham soket + root
  ister. Bu araç OOB (`MSG_OOB`) dışında bu sınıf teknikleri yapmaz. Çok gelişmiş
  bir DPI hiçbir `record-*` / `split` / `oob` stratejisini geçirmiyorsa
  zapret/Xray'a geç.
- Bu bir **VPN değildir** — IP'ni gizlemez.
- Düz HTTP tarafı basittir: her istek `Connection: close` ile tek seferlik.

## Amaç

Erişimi sansürlenmiş açık internete ulaşmak içindir. Kendi cihazında ve
yürürlükteki yasalara uygun kullan.
