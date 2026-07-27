# X-Rae — Referensi Command

Dua nama, satu huruf beda, gampang ketuker — jadi ingat ini dulu:

| Kamu ketik | Itu apa | Contoh |
|---|---|---|
| `xrae` | **command CLI** (dijalankan manual) | `xrae doctor`, `xrae explain ab12cd34` |
| `xrae` (service) | **service systemd** (jalan terus di background) | `systemctl start xrae`, `journalctl -u xrae -f` |

Command CLI dan service systemd sekarang **sama-sama `xrae`**. Path standar: config di `/etc/xrae/config.json`, kredensial di `/etc/xrae/xrae.env`, state di `/var/lib/xrae/state.json`, kode di `/opt/xrae`.

---

## Flag global

Berlaku untuk semua command.

| Flag | Guna | Default |
|---|---|---|
| `-c`, `--config <path>` | Lokasi `config.json` | `/etc/xrae/config.json` (atau env `XRAE_CONFIG`) |
| `--dry-run` | Bikin aksi **mustahil secara teknis** (pakai NoopEnforcer), cuma lapor niat | mati |
| `-v`, `--verbose` | Log level `debug` | log level dari config |
| `-h`, `--help` | Tampilkan bantuan | — |

Kredensial **tidak** lewat flag. Taruh di `xrae.env` di sebelah `config.json` (otomatis dibaca), atau sebagai environment variable. Lihat `xrae.env.example`.

---

## Command

### `xrae init`
Setup interaktif. Menanya 6 hal, menulis `config.json` (0644, aman dibagikan) + `xrae.env` (0600, rahasia) ke lokasi yang sama.

```bash
sudo xrae init --config /etc/xrae/config.json
```
Tidak menimpa file yang sudah ada. Kalau `config.json` sudah ada, dia berhenti tanpa mengubah apa pun.

---

### `xrae doctor`
Cek kesiapan **tanpa** memindai apa pun: versi Node, izin file, akses folder volume, konektivitas panel, dari mana tiap kredensial berasal, lalu cetak kebijakan yang berlaku. Tiap masalah disertai cara memperbaikinya.

```bash
sudo -u xrae xrae doctor --config /etc/xrae/config.json
```
Jalankan ini **setiap kali** habis ubah config/kredensial. Baris volume yang muncul sebagai `!` (bukan `✗`) di shell manual itu normal: shell manual tak punya capability, service systemd punya `CAP_DAC_READ_SEARCH`.

---

### `xrae scan`
Jalankan **satu** siklus lalu keluar. Untuk uji coba, bukan operasi harian.

```bash
# Lihat yang akan dilakukan tanpa dia melakukan apa pun (paling sering dipakai)
sudo -u xrae xrae scan --config /etc/xrae/config.json --dry-run --verbose

# Satu siklus sungguhan (tetap observe = cuma mencatat)
sudo -u xrae xrae scan --config /etc/xrae/config.json
```
Flag relevan: `--dry-run`, `--verbose`, `--config`.

---

### `xrae run`
Jalan **terus-menerus**: scan → tidur `scanner.intervalMinutes` (default 15 menit) → scan lagi. **Ini yang dipakai systemd** — jarang diketik manual.

```bash
xrae run --config /etc/xrae/config.json    # biasanya via: systemctl start xrae
```
Siklus pertama jalan **seketika** (jeda 15 menit itu antar-siklus, bukan penundaan awal). Berhenti bersih saat menerima SIGTERM/SIGINT (menyelesaikan server yang sedang diproses lalu keluar).

---

### `xrae explain <id>`
Tampilkan bukti tersimpan untuk satu server: skor, skor setelah decay, jumlah trip berturut-turut, aksi terakhir, dan daftar bukti per rule. `<id>` = identifier pendek server (8 karakter, sama seperti di panel).

```bash
xrae explain 1b3b9959 --config /etc/xrae/config.json
```
Ada karena satu aturan: kalau tak bisa dijelaskan ke pelanggan kenapa ditindak, jangan ditindak.

---

### `xrae notify-test`
Kirim **satu** notice percobaan ke webhook Discord, untuk membuktikan webhook jalan sebelum dipercaya membawa alert sungguhan.

```bash
sudo -u xrae xrae notify-test --config /etc/xrae/config.json
```
Gagal dengan pesan jelas kalau webhook belum di-set / salah / dihapus di sisi Discord.

---

### `xrae version`
Cetak versi. `xrae -h` / `xrae --help` menampilkan bantuan.

```bash
xrae version
```

---

## Mengelola service

```bash
sudo systemctl start xrae      # mulai (jalan terus)
sudo systemctl stop xrae       # hentikan
sudo systemctl restart xrae    # restart (habis ubah config / git pull)
sudo systemctl status xrae     # status + log terakhir
sudo systemctl enable xrae     # auto-start saat boot (install.sh sudah lakukan)
journalctl -u xrae -f          # ikuti log live
journalctl -u xrae -n 200 --no-pager   # 200 baris terakhir
```

Config diubah? `systemctl restart xrae`. Kode di-update (`git pull`)? `bash install.sh` lalu `systemctl restart xrae`.

---

## Tangga mode (`policy.mode` di config)

| Mode | Yang boleh dilakukan |
|---|---|
| `observe` | catat saja — **mulai di sini** |
| `alert` | beri tahu manusia, jangan sentuh server |
| `throttle` | turunkan CPU quota (butuh WingsEnforcer, belum ada) |
| `enforce` | boleh suspend, dengan semua guardrail aktif |

Ganti mode: edit `config.json` atau set `XRAE_MODE`, lalu `systemctl restart xrae`.

---

## Alur pemakaian pertama

```bash
sudo xrae init                                     # 1. buat config + env
sudo nano /etc/xrae/xrae.env                       # 2. isi key panel + webhook
sudo -u xrae xrae doctor                           # 3. buktikan semua jalan
sudo -u xrae xrae scan --dry-run --verbose         # 4. lihat tanpa bertindak
sudo systemctl start xrae && journalctl -u xrae -f # 5. jalankan
```
Biarkan di `observe` beberapa minggu. Nilai temuan dengan `xrae explain`, matikan rule berisik lewat `exclusions.ruleIds` di config, baru naikkan mode.
