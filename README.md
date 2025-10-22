# GhostScan — Tools Scanner By GhostF4j

**Deskripsi singkat**
GhostScan men-scan port umum & mencoba grab banner. Ada pre-check (3 pertanyaan) dan proteksi administratif untuk IP publik. Setelah scan, tool akan menampilkan status dengan format yang diminta (WARNING / Info).

**Fitur utama**
- Tiga pertanyaan verifikasi sebelum lanjut (nama, tujuan, persetujuan).
- Proteksi administratif untuk IP publik (harus mengetik `I_HAVE_PERMISSION` dan memasukkan email pemilik).
- Scan port umum (multi-threaded) dan pembacaan banner singkat.
- Klasifikasi hasil sederhana: akan menampilkan WARNING jika terdeteksi port berisiko atau jumlah port terbuka signifikan.
- Tampilan "hacker" (ASCII-art + ANSI colors) setelah verifikasi.
- Logging aktivitas ke `ghostscan_log.txt`.

## Persyaratan
- **Python 3.6+** (jalankan dengan `python3 main.py`)
- (Opsional, untuk Windows) `colorama` agar ANSI colors bekerja lebih rapi

## Instalasi & jalankan
1. Pastikan file `main.py` dan `README.md` ada di satu folder.
2. Gunakan Python 3: pada Termux/Linux/macOS jalankan:

   ## Instalasi package via termux
   `pkg update && pkg upgrade -y`
   `pkg install python git nmap nano -y`
`python -m pip install --upgrade pip`
`pip install colorama`
`cd /path/ke/folder/ghostscan`
# pastikan file ada: main.py
`chmod +x main.py`
`python3 main.py`

   ## instalasi package via linux
   `sudo apt update && sudo apt upgrade -y`
`sudo apt install python3`
`python3-pip python3-venv git nmap net-tools tcpdump -y`
