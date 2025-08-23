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
EXCLUSIONS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]  # Windows varsayılan

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
        append_output(f"[!] Zararlı karantinaya alındı: {path}")
    except Exception as e:
        append_output(f"[!] Karantinaya alınamadı: {e}")

# ---------------------- OUTPUT YAZDIRMA ----------------------
def append_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

# ---------------------- TARAMA ----------------------
def scan_path(root, signatures, show_all=False):
    for dirpath, dirnames, filenames in os.walk(root):
        if any(dirpath.startswith(ex) for ex in EXCLUSIONS):
            continue
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            if show_all:
                append_output(f"[Tarandı] {fpath}")
            sha = hash_file(fpath)
            if sha and sha in signatures:
                quarantine(fpath, sha)

# ---------------------- QUICK SCAN ----------------------
def quick_scan():
    append_output("[*] Quick Scan başlatıldı...")
    signatures = load_signatures()
    for folder in [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]:
        if os.path.exists(folder):
            scan_path(folder, signatures)
    append_output("[*] Quick Scan tamamlandı.")

# ---------------------- FULL SCAN ----------------------
def full_scan():
    # Platforma göre kök dizini belirle
    system = platform.system()
    if system == "Windows":
        folder = "C:/"
    else:
        folder = "/"
    append_output(f"[*] Full Scan başlatıldı: {folder}")
    signatures = load_signatures()
    scan_path(folder, signatures, show_all=True)
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
