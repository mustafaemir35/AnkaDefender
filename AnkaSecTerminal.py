import os
import hashlib
import shutil
import time
import json
from datetime import datetime

# Ayarlar
QUARANTINE_DIR = os.path.expanduser("~/.ankasec/quarantine")
SIGNATURE_FILE = os.path.expanduser("~/.ankasec/signatures/sha256_blacklist.txt")
LOG_FILE = os.path.expanduser("~/.ankasec/log.json")
EXCLUSIONS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]

# Dizini hazırla
def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(SIGNATURE_FILE), exist_ok=True)

# İmzaları yükle
def load_signatures():
    if not os.path.exists(SIGNATURE_FILE):
        return set()
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

# Dosya hash
def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# Log kaydı
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

# Karantinaya al
def quarantine(path, sha):
    try:
        fname = os.path.basename(path)
        qname = os.path.join(QUARANTINE_DIR, f"Q_{sha[:12]}_{fname}")
        shutil.move(path, qname)
        log_event({"event": "quarantine", "file": path, "sha256": sha})
        print(f"[!] Zararlı karantinaya alındı: {path}")
    except Exception as e:
        print(f"[!] Karantinaya alınamadı: {e}")

# Tarama
def scan_path(root, signatures, show_all=False):
    for dirpath, dirnames, filenames in os.walk(root):
        if any(dirpath.startswith(ex) for ex in EXCLUSIONS):
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            if show_all:
                print(f"[Tarandı] {fpath}")
            sha = hash_file(fpath)
            if sha and sha in signatures:
                quarantine(fpath, sha)

# Quick scan
def quick_scan():
    print("[*] Quick Scan başlatıldı...")
    signatures = load_signatures()
    for folder in [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]:
        if os.path.exists(folder):
            scan_path(folder, signatures)
    print("[*] Quick Scan tamamlandı.")

# Full scan
def full_scan(root="C:/"):
    print("[*] Full Scan başlatıldı...")
    signatures = load_signatures()
    scan_path(root, signatures, show_all=True)
    print("[*] Full Scan tamamlandı.")

# Başlat
if __name__ == "__main__":
    ensure_dirs()
    try:
        print("Hangi taramayı yapmak istiyorsunuz?")
        print("1) Quick Scan (Downloads + Desktop)")
        print("2) Full Scan (C:/ tüm sistem)")
        choice = input("Seçiminiz (1 veya 2): ").strip()
        if choice == "1":
            quick_scan()
        elif choice == "2":
            full_scan()
        else:
            print("[!] Geçersiz seçim, Quick Scan varsayılan olarak çalıştırılıyor.")
            quick_scan()
    except KeyboardInterrupt:
        print("\n[!] Tarama kullanıcı tarafından durduruldu.")
    input("Tarama tamamlandı. Çıkmak için ENTER'a basın...")
