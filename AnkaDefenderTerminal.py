import os
import hashlib
import shutil
import json
from datetime import datetime
import threading
import platform
from plyer import notification
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------- AYARLAR ----------------------
QUARANTINE_DIR = os.path.expanduser("~/.ankantivirus/quarantine")
LOG_FILE = os.path.expanduser("~/.ankantivirus/log.json")
EXCLUSIONS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]

# ---------------------- TEST İMZASI ----------------------
TEST_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

# ---------------------- DİZİN HAZIRLAMA ----------------------
def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

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

# ---------------------- ÇIKTI EKLE ----------------------
def append_output(text):
    print(text)

# ---------------------- KARANTİNAYA AL ----------------------
def quarantine(path, sha):
    try:
        fname = os.path.basename(path)
        qname = os.path.join(QUARANTINE_DIR, f"Q_{sha[:12]}_{fname}")
        shutil.move(path, qname)
        log_event({"event": "quarantine", "file": path, "sha256": sha})
        append_output(f"[!] Karantinaya alındı: {path}")
    except Exception as e:
        append_output(f"[!] Karantinaya alınamadı: {e}")

# ---------------------- TARAMA ----------------------
def scan_path(root):
    found_malware = []
    for dirpath, dirnames, filenames in os.walk(root):
        if any(dirpath.startswith(ex) for ex in EXCLUSIONS):
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            append_output(f"[Tarandı] {fpath}")
            sha = hash_file(fpath)
            if sha and sha in TEST_SIGNATURES:
                quarantine(fpath, sha)
                found_malware.append(fpath)
    return found_malware

# ---------------------- QUICK SCAN ----------------------
def quick_scan():
    append_output("[*] Quick Scan başlatıldı...")
    found_all = []
    for folder in [os.path.expanduser("/Downloads"), os.path.expanduser("/Desktop")]:
        if os.path.exists(folder):
            found_all.extend(scan_path(folder))
    show_report(found_all, "Quick Scan")

# ---------------------- FULL SCAN ----------------------
def full_scan():
    system = platform.system()
    folder = "C:/" if system == "Windows" else "/"
    append_output(f"[*] Full Scan başlatıldı: {folder}")
    found_all = scan_path(folder)
    show_report(found_all, "Full Scan")

# ---------------------- RAPOR ----------------------
def show_report(found_all, scan_type):
    append_output("\n=== SONUÇ RAPORU ===")
    if found_all:
        append_output("[!] Zararlı dosyalar bulundu:")
        for f in found_all:
            append_output(f" - {f}")
        append_output(f"[!] Son zararlı dosya: {found_all[-1]}")
    else:
        append_output("[*] Zararlı dosya bulunamadı.")
    append_output(f"[*] {scan_type} tamamlandı.\n")

# ---------------------- THREAD ----------------------
def threaded_scan(scan_func):
    t = threading.Thread(target=scan_func)
    t.start()
    t.join()  # Terminalde bekleyelim ki çıktıyı görelim

# ---------------------- GERÇEK ZAMANLI TARAMA ----------------------
class RealTimeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        fpath = event.src_path
        append_output(f"[Yeni Dosya] {fpath}")
        sha = hash_file(fpath)
        if sha and sha in TEST_SIGNATURES:
            quarantine(fpath, sha)
            append_output(f"[!] Zararlı dosya bulundu ve karantinaya alındı: {fpath}")
            notification.notify(
                title="AnkaAntivirüs - Uyarı",
                message=f"Zararlı dosya tespit edildi:\n{fpath}",
                app_name="AnkaAntivirüs",
                timeout=5
            )

def start_realtime_scan():
    paths_to_watch = [os.path.expanduser("/Downloads"), os.path.expanduser("/Desktop")]
    event_handler = RealTimeHandler()
    observer = Observer()
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
    observer.start()
    append_output("[*] Gerçek zamanlı tarama başlatıldı...")
    try:
        while True:
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def start_realtime_thread():
    t = threading.Thread(target=start_realtime_scan, daemon=True)
    t.start()
    t.join()

# ---------------------- TERMINAL MENÜ ----------------------
def terminal_menu():
    ensure_dirs()
    while True:
        print("\n=== AnkaAntivirüs Terminal ===")
        print("1. Quick Scan")
        print("2. Full Scan")
        print("3. Gerçek Zamanlı Tarama")
        print("4. Çıkış")
        choice = input("Seçiminiz: ").strip()
        if choice == "1":
            threaded_scan(quick_scan)
        elif choice == "2":
            threaded_scan(full_scan)
        elif choice == "3":
            print("[!] Gerçek zamanlı tarama başlatıldı. Ctrl+C ile durdurabilirsiniz.")
            start_realtime_scan()
        elif choice == "4":
            print("Çıkış yapılıyor...")
            break
        else:
            print("Geçersiz seçim!")

# ---------------------- MAIN ----------------------
if _name_ == "_main_":
    terminal_menu()
