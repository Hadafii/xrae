# Arsitektur X-Rae

Dokumen ini untuk siapa pun yang akan mengubah kode ini — termasuk kamu, enam
bulan dari sekarang, ketika sudah lupa alasannya.

**Baca ini dulu, lalu `src/composition-root.js`.** Dua file itu cukup untuk
memahami seluruh sistem.

---

## 1. Satu aturan yang harus diingat

```
        domain/  ←  application/  ←  infrastructure/  ←  cli/
       (murni)      (alur kerja)      (dunia luar)      (perintah)

                    Panah = "boleh import"
```

| Layer | Boleh import | Isinya |
|---|---|---|
| `domain/` | **hanya `domain/`** | Aturan bisnis. Nol I/O. Tidak ada `node:fs`, tidak ada npm, tidak ada jam. |
| `application/` | `domain/` + `application/` | Alur kerja. Bicara ke dunia luar **hanya** lewat `ports.js`. |
| `infrastructure/` | apa saja | Adapter nyata: HTTP, filesystem, Pterodactyl, Discord. |
| `cli/` | apa saja | Perintah yang diketik operator. |
| `composition-root.js` | apa saja | **Satu-satunya** file yang memilih class konkret mana dipakai. |

### Aturan ini tidak ditegakkan oleh niat baik

Clean architecture biasanya rusak karena diagramnya cuma ada di wiki. Enam bulan
kemudian seseorang meng-import database client ke dalam file domain karena lebih
cepat, review tidak menangkapnya, dan batas layer-nya hilang.

`test/architecture.test.mjs` membaca statement `import` yang sebenarnya dan
**menggagalkan build** kalau aturan di atas dilanggar. Coba sendiri:

```bash
echo "import fs from 'node:fs';" >> src/domain/scoring.js
npm test        # gagal, dengan pesan yang menjelaskan kenapa
```

Kalau kamu perlu melanggar salah satu aturan itu, hampir pasti yang bermasalah
adalah desainnya, bukan test-nya.

---

## 2. Struktur file

```
xrae/
├── bin/xrae                        entry point (7 baris, sengaja)
├── src/
│   ├── domain/                     MURNI — bisa dites tanpa apa pun
│   │   ├── confidence.js           tingkat keyakinan + perbandingannya
│   │   ├── evidence.js             apa itu satu bukti
│   │   ├── scoring.js              fusi bukti: dedupe, cap, korroborasi, decay
│   │   ├── policy.js               tangga respons + guardrail anti-cascade
│   │   └── rules.js                rule pack (data) + validatornya
│   │
│   ├── application/                ALUR KERJA — hanya kenal port
│   │   ├── ports.js                SEMUA kontrak, dalam satu file
│   │   ├── collect-evidence.js     jalankan semua collector, isolasi kegagalan
│   │   └── run-scan-cycle.js       satu siklus penuh, dua fase
│   │
│   ├── infrastructure/             DUNIA LUAR — implementasi port
│   │   ├── http/                   retry + circuit breaker
│   │   ├── panel/                  tiga adapter Pterodactyl
│   │   ├── filesystem/             walker aman + analyzer file
│   │   ├── collectors/             filesystem, cpu, network
│   │   ├── notification/           Discord Components V2 + fallback console
│   │   ├── persistence/            state JSON, tulis atomik
│   │   └── system/                 logger, clock, resolver container
│   │
│   ├── config/config.js            load, merge env, validasi
│   ├── cli/                        init, doctor, scan, run, explain
│   └── composition-root.js         ← BACA INI KEDUA
│
├── test/                           70 test, nol dependensi
└── systemd/xrae.service
```

---

## 3. SOLID, dengan contoh nyata dari kode ini

Bukan daftar hafalan. Ini lokasi persisnya dan apa yang dibeli.

### S — Single Responsibility

Setiap file punya **satu alasan untuk berubah**. Tes cepat: kalau kamu tidak
bisa menjelaskan isi file dalam satu kalimat, file itu terlalu besar.

Contoh pemisahan yang tampak berlebihan tapi tidak:

- `safe-walker.js` — menemukan file. Tidak membacanya.
- `file-analyzer.js` — membaca file. Tidak mencarinya.
- `filesystem-collector.js` — menyambungkan keduanya. 60 baris.

Kenapa dipisah: aturan keamanan traversal (symlink, FIFO, budget) berubah karena
alasan yang sama sekali berbeda dari aturan deteksi konten. Menggabungkannya
berarti setiap perubahan rule pack menyentuh kode yang menjaga kita dari
container escape.

Contoh lain: `components-v2-builder.js` membentuk pesan, `discord-notifier.js`
mengirimnya. Karena itu bentuk payload bisa diuji tanpa jaringan sama sekali.

### O — Open/Closed

Menambah kemampuan tanpa mengubah kode yang sudah jalan.

- **Tambah aturan deteksi** → tambah satu entry data di `rules.js`. Engine tidak
  disentuh.
- **Tambah sumber bukti** → tulis collector baru, daftarkan di composition root.
  `run-scan-cycle.js` dan `scoring.js` tidak disentuh.
- **Tambah kemampuan throttle** → tulis `WingsEnforcer`, ganti satu baris.
  Domain tidak disentuh — `ResponseLevel.THROTTLE` sudah ada dan policy sudah
  bisa memutuskannya.

Itu bukan teori. `PterodactylEnforcer.supports()` sudah mengembalikan `false`
untuk throttle, dan use case sudah menurunkan ke alert dengan jujur.

### L — Liskov Substitution

Semua implementasi `EvidenceCollector` mematuhi kontrak yang sama, termasuk
bagian tidak menyenangkannya:

> Kembalikan array. Jangan pernah `null`. Kembalikan array **kosong** kalau
> sumber datanya tidak tersedia. **Jangan throw.**

Karena itu `NetworkCollector` yang tidak punya izin baca `/proc` tetap bisa
ditukar dengan yang punya, tanpa satu pun `if` di pemanggilnya. Dan
`EvidenceCollectionService` tetap menangkap exception sebagai jaring pengaman —
collector yang rusak tidak boleh menghentikan collector lain.

Lihat test: `one broken collector does not stop the others`.

### I — Interface Segregation

Ini yang paling sering di-skip orang, dan di sini membeli sesuatu yang konkret.

`src/infrastructure/panel/pterodactyl.js` berisi **tiga** class kecil, bukan satu
`PanelClient` gemuk:

| Class | Kemampuan |
|---|---|
| `PterodactylServerRepository` | baca daftar server — **tidak bisa mengubah apa pun** |
| `PterodactylMetricsProvider` | baca CPU — **tidak bisa mengubah apa pun** |
| `PterodactylEnforcer` | suspend — **satu-satunya yang punya kuasa** |

Kalau ini satu class, maka setiap objek yang memegang referensinya juga memegang
kemampuan men-suspend server pelanggan, dibutuhkan atau tidak. Sekarang hanya
use case yang memegang enforcer.

### D — Dependency Inversion

`domain/` dan `application/` tidak tahu Pterodactyl atau Discord itu ada. Mereka
hanya kenal kontrak di `ports.js`. Yang menyambungkan ke implementasi nyata cuma
`composition-root.js`.

Hasil nyatanya ada di `test/integration.test.mjs`: use case yang diuji adalah
**kode produksi yang sama persis**, tapi setiap batas sistem diganti stub lima
baris. Tanpa jaringan, tanpa temp file, tanpa menunggu.

---

## 4. Resep: cara melakukan hal yang sering dilakukan

### Menambah aturan deteksi

1. Buka `src/domain/rules.js`, tambahkan entry ke `RULE_PACK`.
2. **Isi `fpProfile`.** Wajib — validator menolak aturan tanpanya. Jawab:
   "kapan aturan ini menyalakan alarm untuk server yang tidak bersalah?"
   Kalau tidak bisa dijawab, aturannya belum siap.
3. Set `standalone: true` **hanya** kalau tidak ada alasan sah sebuah game server
   memuat string itu. URL stratum lolos. Kata `xmrig` tidak — kata itu muncul di
   blocklist, log, dan tool keamanan.
4. `npm test`, lalu jalankan mode observe seminggu sebelum percaya.

### Menambah sumber bukti baru

1. Buat class di `src/infrastructure/collectors/`, patuhi kontrak
   `EvidenceCollector` di `ports.js`.
2. Daftarkan di array `collectors` di `composition-root.js`.
3. Selesai. Tidak ada file lain yang berubah.

### Mengganti Discord ke Slack

1. Tulis `SlackNotifier` yang memenuhi kontrak `Notifier`.
2. Ganti satu baris di composition root.

### Menambah throttle (yang paling saya sarankan berikutnya)

1. Tulis `WingsEnforcer` yang bicara ke Wings API, `supports('throttle')`
   mengembalikan `true`.
2. Ganti satu baris di composition root.
3. Set `"mode": "throttle"` di config.

Domain sudah siap. `ResponseLevel.THROTTLE` dan
`policy.minConfidenceToThrottle` sudah ada dan sudah diuji.

### Menonaktifkan satu aturan tanpa menyentuh kode

```json
{ "exclusions": { "ruleIds": ["tunnel.nezha.agent"] } }
```

---

## 5. Kenapa tidak TypeScript

TypeScript berarti build step. Build step berarti `npm install`, `tsconfig`,
artifact yang berbeda dari sumbernya, dan satu langkah lagi antara "clone repo"
dan "jalan".

Jalan tengahnya: **JSDoc + `jsconfig.json` dengan `checkJs: true`**. Buka
proyek ini di VS Code — hover class atau port mana pun, kontraknya muncul.
Autocomplete jalan. Type error muncul di editor. Tanpa build, tanpa dependensi,
dan yang jalan di produksi adalah file yang sama dengan yang kamu baca.

Kalau nanti proyeknya tumbuh besar, migrasi ke TypeScript gampang justru karena
tipe-tipenya sudah ditulis.

---

## 6. Kenapa nol dependensi npm

X-Rae membaca file milik pelanggan dengan hak istimewa. Satu dependensi yang
dikompromikan berarti seluruh fleet dikompromikan. Dependensi yang tidak ada
tidak bisa disalahgunakan.

Konsekuensi konkretnya:

- Config pakai JSON (dengan komentar `//` diizinkan), bukan YAML — YAML butuh
  paket npm. Pemotong komentarnya ada di `config.js`, sepuluh baris, bisa dibaca
  sekali duduk.
- Test pakai `node:test` bawaan, bukan Jest atau Mocha.
- Tidak ada `npm install` saat instalasi. Sama sekali.

Ini juga ditegakkan test: `the project has zero npm dependencies`.

---

## 7. Yang sengaja TIDAK dibuat abstrak

Karena over-abstraction membuat kode lebih sulit dipahami junior, bukan lebih
mudah. Ini keputusan sadar, bukan kelalaian:

- **Tidak ada DI container.** Composition root adalah fungsi biasa yang `new`
  objek dari atas ke bawah. Bisa dibaca sekali jalan.
- **Tidak ada repository pattern untuk file.** `FileContentAnalyzer` memakai
  `node:fs` langsung. Meng-abstraksi filesystem hanya menambah lapisan tanpa
  menambah kemampuan apa pun.
- **Tidak ada event bus.** Alurnya linear dan berurutan; event bus hanya membuat
  urutannya jadi tidak jelas.
- **Tidak ada factory untuk objek yang cuma satu jenis.**
- **Cancellation pakai `{ aborted: boolean }`**, bukan `AbortController`. Use
  case hanya perlu bertanya "berhenti?", dan boolean lebih mudah diikuti
  pendatang baru.

Ujiannya selalu sama: **apakah abstraksi ini membuat perubahan nyata jadi lebih
mudah?** Kalau tidak, dia hanya biaya.

---

## 8. Menjalankan test

```bash
npm test                                  # semuanya, 70 test, ~0.5 detik
node --test test/architecture.test.mjs    # cuma aturan layer
node --test test/domain.test.mjs          # cuma logika murni
```

Yang diuji, dan kenapa itu yang dipilih:

| File | Menjaga |
|---|---|
| `architecture.test.mjs` | batas layer, nol dependensi, setiap aturan punya `fpProfile` |
| `domain.test.mjs` | matematika skoring, decay, setiap guardrail |
| `infrastructure.test.mjs` | symlink & FIFO tidak pernah dibuka, retry, redaksi kredensial, kontrak Components V2 |
| `integration.test.mjs` | siklus penuh: cascade tertahan, collector rusak diisolasi, dry run benar-benar tidak bisa bertindak |

Semua test yang menyangkut keamanan ditulis sebagai **properti**, bukan contoh:
"symlink tidak pernah diserahkan ke analyzer" akan tetap gagal meski
implementasinya diganti total.
