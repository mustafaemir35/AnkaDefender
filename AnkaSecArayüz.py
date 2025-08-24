muzlu tafa
mustakarha
Ekranını paylaşıyor

im not real — dün 12:47
günde 4 saat ders ama 2 dk oyun sohbet olunca yarrak
muzlu tafa
[TETO]
 — dün 12:47
sıkıntı
im not real — dün 12:50
ablamla mesaj
yok işte yapması kolaymış
bok kolay
daha print yapamaz o amk ne diyon sen
mac user
💀
muzlu tafa
[TETO]
 — dün 12:51
özellikle macbook alan birisinden ne beklersinki
im not real — dün 12:54
MUSTİ
BABANSA
GÖSTERSENE
im not real — dün 13:04
Ek dosya türü: unknown
AnkaSecArayüz.exe
10.00 MB
import os
import hashlib
import shutil
import json
from datetime import datetime
import tkinter as tk
Genişlet
AnkaSecArayüz.py
5 KB
im not real — dün 13:24
Görsel
Görsel
muzlu tafa
[TETO]
 — dün 20:24
im not real
 kullanıcısından gelen ve 3 dakika süren bir cevapsız arama. — dün 20:39
im not real — dün 20:39
knk
gel
işimiz var
anladın sne
im not real
 kullanıcısından gelen ve birkaç saniye süren bir cevapsız arama. — dün 20:42
im not real
, birkaç saniye süren bir arama başlattı. — dün 20:42
im not real
, 4 dakika süren bir arama başlattı. — dün 20:43
im not real — dün 20:53
.
imanlı demi
im not real
 kullanıcısından gelen ve 3 dakika süren bir cevapsız arama. — dün 21:10
im not real — dün 21:13
lan
bir dm gelmedin
im not real — 12:48
Görsel
Görsel
haddini bildir
yoksa ben yaparım
muzlu tafa
[TETO]
 — 12:49
kendisi yapsın
virüs falan diyor
im not real — 12:49
açık kaynağın ne olduğunu bilmiyo daha
muzlu tafa
[TETO]
 — 12:49
git hub u ilk defa duyuyor
dün toprak tarama yaptırıyodu
bizim antivirüsle 
im not real — 12:50
sonra
normal artık kullanıyor
muzlu tafa
[TETO]
 — 12:50
ayn
im not real — 12:51
muzlu tafa
[TETO]
 — 12:52
im not real — 12:55
laf atarsa beni savun
muzlu tafa
[TETO]
 — 12:55
zaten olm
yazamıyo şu anda
im not real — 12:57
cevap versnee
muzlu tafa
[TETO]
 — 12:58
knk ben bu kodları biraz değiştirmeye çalişicam belki iyi bişiler çıkartırım
im not real — 12:58
yapm
a
muzlu tafa
[TETO]
 — 12:58
2.versiyon olarak atıcam
atarsam
aga benim kodda bi yararım yokki
bide bende yapayimde katkım var derim
im not real — 12:59
KNK
yapmasanda
öylesein
uğraşma
sen onun yerine
nasıl exenin photosu değişiril onu öğren
im not real
 bir arama başlattı. — 13:00
muzlu tafa
[TETO]
 — 13:00
oky
im not real — 13:02
print ("abi yaptığınız kolay ya anlarsın ya çok hawliyim")
muzlu tafa
[TETO]
 — 13:02
ctrl c ctrl v
im not real — 13:21
https://youtu.be/StysIB-Xaxk?si=DQzx8wC2USEQj1dm
YouTube
TheTekkitRealm
I Made My PC Background Tech Support Scammer's Personal Photos
Görsel
muzlu tafa
[TETO]
 — 13:23
https://drive.google.com/file/d/1STt8oCzqfR83783rSjepv7f9bmMTsHPA/view?usp=sharing
Google Docs
AnkaSecArayüza.exe
muzlu tafa
[TETO]
 — 13:36
https://github.com/mustafaemir35/AnkaSec/releases/tag/Antivirus
GitHub
Release AnkaSec · mustafaemir35/AnkaSec
AnkaSec Antivirüs
Release AnkaSec · mustafaemir35/AnkaSec
im not real — 14:07
im not real — 14:45
amk
kendi odası var
orda ders çalışmak erine
gelmiş
benim odada çalışıyo
muzlu tafa
[TETO]
 — 14:46
gıcıklığına yapıyo
im not real — 14:46
knk
Ek dosya türü: unknown
AnkaSec.exe
10.00 MB
düzgün hali burada
o yapmıyormul
ş
muzlu tafa
[TETO]
 — 14:47
dur sıkıntılı olmayabilir bu
biz virüs yükleyemdik
im not real — 14:47
sıkıntılıymış kontrol  ettirdim chatgptye
muzlu tafa
[TETO]
 — 14:48
olsun çalışsın bu belki sorunlu değildir
yada sorunlu ya bu
im not real — 14:49
fbi malware
muzlu tafa
[TETO]
 — 14:49
ayn
virüs ne yüklüyücez biz aq
im not real — 14:54
terminal halini yapıyorum
arayüz tamam
al
Ek dosya türü: unknown
AnkaSecTerminal.exe
7.09 MB
kapat
ok
muzlu tafa
[TETO]
 — 14:55
py dosyasını atsana
ben 2 dk ya geliyom
im not real — 14:56
import os
import hashlib
import shutil
import json
from datetime import datetime
import threading
Genişlet
AnkaSecTerminal.py
5 KB
import os
import hashlib
import shutil
import json
from datetime import datetime
import tkinter as tk
import threading
import platform

# ---------------------- AYARLAR ----------------------
QUARANTINE_DIR = os.path.expanduser("~/.ankasec/quarantine")
SIGNATURE_FILE = os.path.expanduser("~/.ankasec/signatures/sha256_blacklist.txt")
LOG_FILE = os.path.expanduser("~/.ankasec/log.json")
EXCLUSIONS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]

# ---------------------- DİZİN HAZIRLAMA ----------------------
def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(SIGNATURE_FILE), exist_ok=True)

# ---------------------- İMZALARI YÜKLE ----------------------
def load_signatures():
    if not os.path.exists(SIGNATURE_FILE):
        return set()
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

# ---------------------- DOSYA HASH ----------------------
def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---------------------- LOG KAYDI ----------------------
def log_event(event):
    data = {"time": datetime.now().isoformat(), **event}
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(data)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

# ---------------------- KARANTİNAYA AL ----------------------
def quarantine(path, sha):
    try:
        fname = os.path.basename(path)
        qname = os.path.join(QUARANTINE_DIR, f"Q_{sha[:12]}_{fname}")
        shutil.move(path, qname)
        log_event({"event": "quarantine", "file": path, "sha256": sha})
    except Exception as e:
        append_output(f"[!] Karantinaya alınamadı: {e}")

# ---------------------- OUTPUT YAZDIRMA ----------------------
def append_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

# ---------------------- TARAMA ----------------------
def scan_path(root, signatures):
    found_malware = []
    for dirpath, dirnames, filenames in os.walk(root):
        if any(dirpath.startswith(ex) for ex in EXCLUSIONS):
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            append_output(f"[Tarandı] {fpath}")  # dosya akışı
            sha = hash_file(fpath)
            if sha and sha in signatures:
                quarantine(fpath, sha)
                found_malware.append(fpath)
    return found_malware

# ---------------------- QUICK SCAN ----------------------
def quick_scan():
    append_output("[*] Quick Scan başlatıldı...")
    signatures = load_signatures()
    found_all = []
    for folder in [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]:
        if os.path.exists(folder):
            found_all.extend(scan_path(folder, signatures))
    if found_all:
        append_output("[!] Zararlı dosyalar bulundu:")
        for f in found_all:
            append_output(f" - {f}")
        append_output(f"[!] Son zararlı dosya: {found_all[-1]}")
    else:
        append_output("[*] Zararlı dosya bulunamadı.")
    append_output("[*] Quick Scan tamamlandı.")

# ---------------------- FULL SCAN ----------------------
... (46 satır kaldı)
Daralt
AnkaSec.py
6 KB
im not real — 15:05
sil direk
tamam uygula
exeleri silcez direk
﻿
import os
import hashlib
import shutil
import json
from datetime import datetime
import tkinter as tk
import threading
import platform

# ---------------------- AYARLAR ----------------------
QUARANTINE_DIR = os.path.expanduser("~/.ankasec/quarantine")
SIGNATURE_FILE = os.path.expanduser("~/.ankasec/signatures/sha256_blacklist.txt")
LOG_FILE = os.path.expanduser("~/.ankasec/log.json")
EXCLUSIONS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]

# ---------------------- DİZİN HAZIRLAMA ----------------------
def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(SIGNATURE_FILE), exist_ok=True)

# ---------------------- İMZALARI YÜKLE ----------------------
def load_signatures():
    if not os.path.exists(SIGNATURE_FILE):
        return set()
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

# ---------------------- DOSYA HASH ----------------------
def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---------------------- LOG KAYDI ----------------------
def log_event(event):
    data = {"time": datetime.now().isoformat(), **event}
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(data)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

# ---------------------- KARANTİNAYA AL ----------------------
def quarantine(path, sha):
    try:
        fname = os.path.basename(path)
        qname = os.path.join(QUARANTINE_DIR, f"Q_{sha[:12]}_{fname}")
        shutil.move(path, qname)
        log_event({"event": "quarantine", "file": path, "sha256": sha})
    except Exception as e:
        append_output(f"[!] Karantinaya alınamadı: {e}")

# ---------------------- OUTPUT YAZDIRMA ----------------------
def append_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

# ---------------------- TARAMA ----------------------
def scan_path(root, signatures):
    found_malware = []
    for dirpath, dirnames, filenames in os.walk(root):
        if any(dirpath.startswith(ex) for ex in EXCLUSIONS):
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            append_output(f"[Tarandı] {fpath}")  # dosya akışı
            sha = hash_file(fpath)
            if sha and sha in signatures:
                quarantine(fpath, sha)
                found_malware.append(fpath)
    return found_malware

# ---------------------- QUICK SCAN ----------------------
def quick_scan():
    append_output("[*] Quick Scan başlatıldı...")
    signatures = load_signatures()
    found_all = []
    for folder in [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]:
        if os.path.exists(folder):
            found_all.extend(scan_path(folder, signatures))
    if found_all:
        append_output("[!] Zararlı dosyalar bulundu:")
        for f in found_all:
            append_output(f" - {f}")
        append_output(f"[!] Son zararlı dosya: {found_all[-1]}")
    else:
        append_output("[*] Zararlı dosya bulunamadı.")
    append_output("[*] Quick Scan tamamlandı.")

# ---------------------- FULL SCAN ----------------------
def full_scan():
    system = platform.system()
    folder = "C:/" if system == "Windows" else "/"
    append_output(f"[*] Full Scan başlatıldı: {folder}")
    signatures = load_signatures()
    found_all = scan_path(folder, signatures)
    if found_all:
        append_output("[!] Zararlı dosyalar bulundu:")
        for f in found_all:
            append_output(f" - {f}")
        append_output(f"[!] Son zararlı dosya: {found_all[-1]}")
    else:
        append_output("[*] Zararlı dosya bulunamadı.")
    append_output("[*] Full Scan tamamlandı.")

# ---------------------- TARAMA THREAD ----------------------
def threaded_scan(scan_func):
    t = threading.Thread(target=scan_func)
    t.start()

# ---------------------- GUI ----------------------
def start_gui():
    global output_text
    root = tk.Tk()
    root.title("AnkaSec Antivirüs")
    root.geometry("700x500")

    tk.Label(root, text="AnkaSec Antivirüs", font=("Arial", 16, "bold")).pack(pady=10)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=5)

    tk.Button(btn_frame, text="Quick Scan", width=20, command=lambda: threaded_scan(quick_scan)).grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="Full Scan", width=20, command=lambda: threaded_scan(full_scan)).grid(row=0, column=1, padx=5)
    tk.Button(btn_frame, text="Çıkış", width=20, command=root.destroy).grid(row=0, column=2, padx=5)

    output_text = tk.Text(root, height=25, width=85)
    output_text.pack(pady=10)

    root.mainloop()

# ---------------------- BAŞLAT ----------------------
if __name__ == "__main__":
    ensure_dirs()
    start_gui()
AnkaSec.py
6 KB
