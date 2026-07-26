# X-Rae

Agent deteksi penyalahgunaan untuk node Pterodactyl — miner, tunnel, C2.
Penerus SonarX, ditulis ulang supaya bisa diaudit, tidak perlu root, dan tidak
men-suspend pelanggan yang tidak bersalah.

**Nol dependensi npm.** Tidak ada `npm install`, tidak ada build step.

---

## Instalasi

```bash
git clone <repo> x-rae && cd x-rae
sudo ./install.sh
```

Lalu tiga perintah:

```bash
sudo xrae init                 # tanya 6 hal, tulis config
sudo nano /etc/x-rae/xrae.env  # tempel API key di sini
sudo -u xrae xrae doctor       # buktikan semuanya jalan
```

`doctor` mengecek versi Node, izin file, akses volume, kredensial panel,
konektivitas, capability opsional, lalu mencetak kebijakan yang sedang berlaku —
dan memberi tahu cara memperbaiki setiap masalah yang ditemukannya.

Lihat dulu apa yang akan dilakukannya, tanpa dia melakukan apa pun:

```bash
sudo -u xrae xrae scan --dry-run --verbose
```

Kalau sudah puas:

```bash
sudo systemctl start x-rae
journalctl -u x-rae -f
```

Default-nya **mode observe**. X-Rae tidak akan menyentuh satu server pun sampai
kamu sengaja mengubahnya. Biarkan begitu beberapa minggu.

---

## Perintah

```
xrae init                 buat config, interaktif
xrae doctor               cek config, kredensial, izin
xrae scan                 satu siklus lalu keluar
xrae scan --dry-run       satu siklus, tindakan dibuat mustahil secara teknis
xrae run                  jalan terus (ini yang dipakai systemd)
xrae explain <id>         tampilkan bukti tersimpan untuk satu server
```

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

## Konfigurasi

File-nya JSON, dan **komentar `//` diizinkan**. JSON bukan YAML karena YAML butuh
dependensi npm, dan agent berhak istimewa dengan nol dependensi tidak bisa
di-backdoor lewat rantai pasok.

Rahasia sebaiknya dari environment, bukan dari file:

```
XRAE_PANEL_APP_KEY      XRAE_PANEL_CLIENT_KEY      XRAE_DISCORD_WEBHOOK
```

X-Rae **menolak start** kalau config bisa dibaca user lain, atau kalau
`panel.url` plaintext http ke host remote. Gagal keras saat boot lebih baik
daripada bocor diam-diam.

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
