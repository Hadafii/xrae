# X-Rae

Agent deteksi penyalahgunaan untuk node Pterodactyl — miner, tunnel, C2.
Penerus SonarX, ditulis ulang supaya bisa diaudit, tidak perlu root, dan tidak
men-suspend pelanggan yang tidak bersalah.

**Nol dependensi npm.** Tidak ada `npm install`, tidak ada build step.

---

## Instalasi

```bash
git clone <repo> xrae && cd xrae
sudo ./install.sh
```

Lalu tiga perintah:

```bash
sudo xrae init            # tanya 6 hal, tulis config.json + xrae.env
sudo -u xrae xrae doctor  # buktikan semuanya jalan
```

`init` menanyakan pengaturan lalu kredensial, dan menulisnya ke **dua file
terpisah** — pengaturan ke `config.json` (0644), kredensial ke `xrae.env`
(0600). Lihat [Konfigurasi](#konfigurasi-dua-file-dua-tugas).

`doctor` mengecek versi Node, izin file, akses volume, konektivitas panel,
capability opsional, **dari mana setiap kredensial sebenarnya berasal**, lalu
mencetak kebijakan yang sedang berlaku — dan memberi tahu cara memperbaiki
setiap masalah yang ditemukannya.

Lihat dulu apa yang akan dilakukannya, tanpa dia melakukan apa pun:

```bash
sudo -u xrae xrae scan --dry-run --verbose
```

Kalau sudah puas:

```bash
sudo systemctl start xrae
journalctl -u xrae -f
```

Default-nya **mode observe**. X-Rae tidak akan menyentuh satu server pun sampai
kamu sengaja mengubahnya. Biarkan begitu beberapa minggu.

---

## Perintah

Referensi lengkap (guna, contoh, semua flag) ada di
**[docs/COMMANDS.md](docs/COMMANDS.md)**. Ringkasnya:

```
xrae init                 buat config, interaktif
xrae doctor               cek config, kredensial, izin
xrae scan                 satu siklus lalu keluar
xrae scan --dry-run       satu siklus, tindakan dibuat mustahil secara teknis
xrae run                  jalan terus (ini yang dipakai systemd)
xrae explain <id>         tampilkan bukti tersimpan untuk satu server
xrae notify-test          kirim satu notice percobaan ke webhook Discord
```

Command CLI dan service systemd sama-sama `xrae`:
`systemctl start xrae`, `journalctl -u xrae -f`.

`xrae notify-test` ada supaya webhook terbukti jalan **sebelum** dipercaya
membawa alert sungguhan — webhook yang dihapus di sisi Discord gagal diam-diam
sampai hari dia dibutuhkan.

`xrae explain` ada karena satu aturan: kalau kita tidak bisa menjelaskan ke
pelanggan kenapa dia ditindak, kita tidak boleh menindaknya.

```
$ xrae explain ab12cd34

  Server ab12cd34
  ───────────────

  stored score        55 (threshold 100)
  consecutive trips   1
  last action         observe
  score after decay   55  (0.0h elapsed)

  Evidence:
    [signature] miner.stratum.tcp
        matched "stratum+tcp://" in blob.bin
```

---

## Tangga respons

Empat mode. Naik satu tingkat hanya setelah tingkat sebelumnya bersih.

| Mode | Yang boleh dilakukan |
|---|---|
| `observe` | catat saja — **mulai di sini** |
| `alert` | beri tahu manusia, jangan sentuh server |
| `throttle` | turunkan CPU quota, jangan pernah suspend |
| `enforce` | boleh suspend, dengan semua guardrail aktif |

`throttle` adalah tingkat paling berharga dan tidak ada di SonarX: menurunkan
CPU quota menghapus hampir seluruh insentif ekonomi mining, bisa dibatalkan
seketika, dan kalau kita salah pelanggan cuma dapat server lebih lambat — bukan
server mati.

> Konsekuensi kebijakannya: **throttle boleh agresif, suspend harus konservatif.**

---

## Guardrail

Semua aktif secara default. Semuanya ada karena aturan buruk tidak boleh bisa
berubah menjadi outage.

| Guardrail | Fungsinya |
|---|---|
| `consecutiveDetections` | harus trip N siklus berturut-turut |
| `minConfidenceToSuspend` | skor tinggi saja tidak cukup |
| `maxActionsPerCycle` | plafon keras per siklus |
| `anomalyAbortRatio` | kalau >25% node trip bersamaan, **hentikan semua tindakan** dan panggil operator |
| `scoreHalfLifeHours` | bukti memudar; noise tidak bisa menumpuk sampai ambang |
| `--dry-run` | tindakan dibuat *mustahil*, bukan cuma dilarang |

Yang paling penting: **anomaly abort**. Tidak ada skenario realistis di mana
seperempat node mulai menambang di detik yang sama. Kalau angka itu muncul,
hipotesis yang jauh lebih mungkin adalah detektornya yang rusak.

---

## Konfigurasi: dua file, dua tugas

| File | Isi | Mode | Boleh dibagikan? |
|---|---|---|---|
| `/etc/xrae/config.json` | pengaturan | 0644 | **ya** — tempel ke thread support tanpa cemas |
| `/etc/xrae/xrae.env` | kredensial | `0640 root:xrae` | **tidak, pernah** |

X-Rae menemukan `xrae.env` **otomatis** karena letaknya di sebelah
`config.json`. systemd juga memuatnya lewat `EnvironmentFile=`, jadi
`xrae doctor` manual dan service yang berjalan melihat nilai yang sama persis.

`xrae init` menulis kedua file itu untukmu. Template-nya ada di
[`xrae.env.example`](xrae.env.example).

Soal mode `0640 root:xrae` — itu bukan kelalaian. Service jalan sebagai user
`xrae` yang tidak berhak istimewa, jadi dia **harus** bisa membaca file ini;
`0600 root:root` membuat unit-nya start lalu gagal autentikasi, dan itu jenis
bug yang menghabiskan satu jam untuk ditemukan. Group-read juga lebih baik
daripada menjadikan `xrae` sebagai owner: agent bisa membaca kredensialnya,
tapi tidak bisa menulisnya ulang. X-Rae tetap menolak start kalau file-nya
world-readable atau group-writable.

### Urutan prioritas

```
1. environment sungguhan   (systemd, atau `export` di shell-mu)   ← menang
2. xrae.env
3. config.json
4. default bawaan
```

Variabel yang sudah ada di environment sungguhan **tidak pernah** ditimpa oleh
file. Itu yang membuat systemd dan menjalankan manual berperilaku identik.

### Menaruh kredensial di dua tempat adalah kesalahan, bukan cadangan

Ini bug senyap yang paling mahal di sistem seperti ini: kamu rotasi key di
`config.json`, tapi key lama masih ada di environment, jadi **yang lama tetap
dipakai** dan tidak ada apa pun yang memberitahu.

`xrae doctor` **gagal keras** kalau itu terjadi, dan menyebutkan file mana yang
menang:

```
  Credential sources:
  ✓ panel application key  /etc/xrae/xrae.env
  ! panel client key       not set
  ✓ Discord webhook        environment

  ✗ panel application key is set in BOTH config.json and /etc/xrae/xrae.env.
    The env file wins. Remove one of them.
```

### Variabel yang dikenali

| Variabel | Menggantikan |
|---|---|
| `XRAE_PANEL_APP_KEY` | `panel.applicationKey` — **wajib** |
| `XRAE_PANEL_CLIENT_KEY` | `panel.clientKey` — opsional, untuk bukti CPU |
| `XRAE_DISCORD_WEBHOOK` | `notify.discordWebhook` — wajib sebelum mode throttle/enforce |
| `XRAE_PANEL_URL` | `panel.url` |
| `XRAE_VOLUMES_PATH` | `scanner.volumesPath` |
| `XRAE_NODE_ID` | `scanner.nodeId` |
| `XRAE_MODE` | `policy.mode` |
| `XRAE_LOG_LEVEL` | `logLevel` |
| `XRAE_STATE_PATH` | `state.path` |
| `XRAE_CONFIG` | lokasi `config.json` |
| `XRAE_ENV_FILE` | lokasi file kredensial (mis. `/run/secrets/xrae.env`) |

### Aturan yang membuat X-Rae menolak start

Gagal keras saat boot lebih baik daripada bocor atau bertindak diam-diam.

- `xrae.env` bisa dibaca user lain → **tolak**
- `config.json` memuat key **dan** bisa dibaca user lain → **tolak**
  (config.json tanpa kredensial di dalamnya boleh 0644 — memaksa 0600 di situ
  hanya security theatre yang mengajari operator mengabaikan peringatan)
- `panel.url` plaintext `http://` ke host remote → **tolak**
- mode `throttle`/`enforce` tanpa webhook → **tolak**, karena bertindak tanpa
  memberi tahu siapa pun tidak bisa diterima

File config-nya JSON, dan **komentar `//` diizinkan**. JSON bukan YAML karena
YAML butuh dependensi npm, dan agent berhak istimewa dengan nol dependensi tidak
bisa di-backdoor lewat rantai pasok.

Menonaktifkan satu aturan tanpa menyentuh kode:

```json
{ "exclusions": { "ruleIds": ["tunnel.nezha.agent"] } }
```

---

## Model hak istimewa

Tidak jalan sebagai root. Unit systemd memberi tepat dua capability:

| Capability | Untuk apa | Wajib? |
|---|---|---|
| `CAP_DAC_READ_SEARCH` | baca file volume milik user lain | ya |
| `CAP_SYS_PTRACE` | baca `/proc/<pid>/net` untuk atribusi per-container | tidak |

Tidak nyaman memberi `CAP_SYS_PTRACE`? Hapus dari unit file dan set
`"collectConnections": false`. Semuanya tetap jalan, kamu hanya kehilangan satu
famili bukti — dan `doctor` akan mengatakannya, bukan diam-diam menghasilkan
data sampah.

---

## Untuk yang akan maintenance

Baca **[ARCHITECTURE.md](ARCHITECTURE.md)**, lalu `src/composition-root.js`.
Dua file itu cukup.

Aturan yang harus diingat cuma satu:

```
domain/  ←  application/  ←  infrastructure/  ←  cli/
                    boleh import →
```

`domain/` tidak boleh import apa pun kecuali `domain/` — bahkan `node:fs`.
`application/` hanya kenal kontrak di `ports.js`.

Ini bukan konvensi yang harus diingat. `test/architecture.test.mjs` membaca
statement `import` yang sebenarnya dan menggagalkan build kalau dilanggar. Coba:

```bash
echo "import fs from 'node:fs';" >> src/domain/scoring.js
npm test    # gagal, dengan penjelasan kenapa
```

Resep untuk tugas yang sering muncul (tambah aturan, tambah sumber bukti, ganti
Discord ke Slack, tambah throttle) ada di ARCHITECTURE.md §4. Semuanya mengubah
satu sampai dua file.

---

## Test

```bash
npm test    # 70 test, ~0.5 detik, tanpa jaringan
```

Yang diuji adalah hal-hal yang kalau rusak akan melukai seseorang: symlink dan
FIFO tidak pernah dibuka, indikator di tengah file tetap ditemukan, satu famili
bukti lemah tidak bisa menembus threshold, decay benar-benar meluruh, cascade
tertahan, collector rusak diisolasi, dan payload Components V2 sesuai kontrak.

Semuanya ditulis sebagai **properti**, bukan contoh — jadi tetap gagal meski
implementasinya diganti total.

---

## Batasan yang jujur

- Deteksi berbasis konten bisa dielakkan penyerang serius (rename, packing,
  mining di memori saja). Nilainya ada di penyalahgunaan oportunistik, yang
  merupakan mayoritas kasus di game hosting.
- Bobot aturan adalah tebakan terdidik, **belum terkalibrasi**. Sampai ada korpus
  server sah berlabel untuk mengukurnya, jangan percayai angkanya untuk
  enforcement otomatis. Ini alasan utama default-nya `observe`.
- Bukan pencegahan. cgroup CPU quota dan egress filtering per-container yang
  mencegah masalahnya; X-Rae hanya mendeteksi. Kalau harus pilih satu, pilih
  pencegahan.
- Kunci admin panel masih ada di node. Arsitektur target memisahkan sensor
  (node, tanpa kredensial) dari controller (pusat, pemegang kunci) — lihat
  design doc. Kode ini sudah disiapkan untuk itu: enforcement ada di balik port,
  jadi memindahkannya ke controller tidak menyentuh `domain/` atau
  `application/`.
