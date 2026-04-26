#!/usr/bin/env python3
import tkinter as tk
import os
import subprocess
import threading
import re
from datetime import datetime
import json
from pathlib import Path

# -----------------------------
# CONFIG
# -----------------------------
def load_config():
    config_path = Path.home() / ".config/suricata-blocker/config.json"

    default = {
        "script_path": "/usr/local/bin/suricata-blocker.sh",
        "block_file": "/tmp/suricata_blocked_ips.txt",
        "superban_file": "/etc/suricata/superbanned_ips.txt"
    }

    if not config_path.exists():
        print("[CONFIG] no config file, using defaults")
        return default

    try:
        with open(config_path, "r") as f:
            user_conf = json.load(f)

        print("[CONFIG] loaded:", user_conf)

        # merge seguro (sin perder defaults)
        for k in default:
            if k in user_conf:
                default[k] = user_conf[k]

    except Exception as e:
        print("[CONFIG ERROR]", e)

    return default

config = load_config()

SCRIPT_PATH = config["script_path"]
BLOCK_FILE = config["block_file"]
SUPERBAN_FILE = config["superban_file"]

REFRESH_MS = 3000

# -----------------------------
# ROOT
# -----------------------------
root = tk.Tk()
root.title("Suricata Blocker GUI Deluxe")
root.update_idletasks()
root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}+0+0")

process = None

# -----------------------------
# STATE
# -----------------------------
selected_blocked_ip = None
selected_superban_ip = None
selected_drop_ip = None

# -----------------------------
# LOG
# -----------------------------
log_frame = tk.LabelFrame(root, text="Logs")
log_frame.pack(fill="x", padx=10, pady=5)

log_text = tk.Text(log_frame, height=8)
log_text.pack(fill="both", expand=True)

def log(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

def safe_log(msg):
    root.after(0, log, msg)

# -----------------------------
# IP PARSING FIX
# -----------------------------
def extract_ip(text):
    if not text:
        return None

    text = text.strip()

    # IP pura
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", text):
        return text

    # IP + metadata
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)", text)
    if m:
        return m.group(1)

    # IP|timestamp
    if "|" in text:
        return text.split("|", 1)[0].strip()

    return None

def parse_superban_line(line):
    ip = extract_ip(line)
    ts = None

    if "|" in line:
        parts = line.split("|", 1)
        if len(parts) == 2:
            ts = parts[1].strip()

    return ip, ts

# -----------------------------
# TIMESTAMP
# -----------------------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------
# START SCRIPT
# -----------------------------
def start_suricata():
    global process

    if process is not None:
        safe_log("[!] Is already running")
        return

    if not os.path.exists(SCRIPT_PATH):
        safe_log("[ERROR] Script not found")
        return

    safe_log("[*] Starting Suricata...")

    process = subprocess.Popen(
        ["bash", SCRIPT_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    threading.Thread(target=read_output, daemon=True).start()

# -----------------------------
# TOP BAR
# -----------------------------
top_bar = tk.Frame(root)
top_bar.pack(fill="x", padx=10, pady=5)

tk.Button(top_bar, text="START", bg="green", fg="white",
          command=start_suricata).pack(side=tk.LEFT, padx=5)

# -----------------------------
# MAIN LAYOUT
# -----------------------------
main = tk.Frame(root)
main.pack(fill="both", expand=True, padx=10, pady=5)

main.columnconfigure(0, weight=0)
main.columnconfigure(1, weight=1)
main.columnconfigure(2, weight=0)
main.columnconfigure(3, weight=1) 
main.rowconfigure(0, weight=1)

# =========================================================
# BLOCKED IPs
# =========================================================
blocked_frame = tk.LabelFrame(main, text="Blocked IPs")
blocked_frame.grid(row=0, column=0, sticky="ns", padx=5)
blocked_frame.grid_propagate(False)
blocked_frame.config(width=200)

blocked_listbox = tk.Listbox(blocked_frame, width=20)
scroll1 = tk.Scrollbar(blocked_frame, command=blocked_listbox.yview)
blocked_listbox.config(yscrollcommand=scroll1.set)

scroll1.pack(side=tk.RIGHT, fill=tk.Y)
blocked_listbox.pack(fill="both", expand=True)

def on_blocked_select(event):
    global selected_blocked_ip
    sel = blocked_listbox.curselection()
    if sel:
        selected_blocked_ip = blocked_listbox.get(sel[0])

blocked_listbox.bind("<<ListboxSelect>>", on_blocked_select)

# =========================================================
# SUPERBAN
# =========================================================
superban_frame = tk.LabelFrame(main, text="SUPERBAN")
superban_frame.grid(row=0, column=1, sticky="nsew", padx=5)

superban_listbox = tk.Listbox(superban_frame)
scroll2 = tk.Scrollbar(superban_frame, command=superban_listbox.yview)
superban_listbox.config(yscrollcommand=scroll2.set)

scroll2.pack(side=tk.RIGHT, fill=tk.Y)
superban_listbox.pack(fill="both", expand=True)

def on_superban_select(event):
    global selected_superban_ip
    sel = superban_listbox.curselection()
    if sel:
        selected_superban_ip = superban_listbox.get(sel[0])

superban_listbox.bind("<<ListboxSelect>>", on_superban_select)

# =========================================================
# DROP ZONE
# =========================================================
drop_frame = tk.LabelFrame(main, text="Firewalld DROP Zone")
drop_frame.grid(row=0, column=2, sticky="ns", padx=5)
drop_frame.grid_propagate(False)
drop_frame.config(width=200)

drop_listbox = tk.Listbox(drop_frame, width=20)
scroll_drop = tk.Scrollbar(drop_frame, command=drop_listbox.yview)
drop_listbox.config(yscrollcommand=scroll_drop.set)

scroll_drop.pack(side=tk.RIGHT, fill=tk.Y)
drop_listbox.pack(fill="both", expand=True)

def on_drop_select(event):
    global selected_drop_ip
    sel = drop_listbox.curselection()
    if sel:
        selected_drop_ip = drop_listbox.get(sel[0])

drop_listbox.bind("<<ListboxSelect>>", on_drop_select)

# =========================================================
# REMOVE FROM DROP ZONE
# =========================================================
def remove_from_drop_zone():
    global selected_drop_ip

    ip = extract_ip(selected_drop_ip)

    if not ip:
        safe_log("[!] Select a valid IP from DROP ZONE")
        return

    safe_log(f"[DROP UNBAN] {ip}")

    subprocess.run([
        "pkexec", "firewall-cmd",
        "--permanent",
        "--zone=drop",
        "--remove-source=" + ip
    ])

    subprocess.run(["pkexec", "firewall-cmd", "--reload"])

    update_drop_zone()

# =========================================================
# FIREWALL
# =========================================================
fw_frame = tk.LabelFrame(main, text="Firewalld status (Drop Zone: INPUT BLOCK - Rich Rule: INPUT/OUTPUT BLOCK)")
fw_frame.grid(row=0, column=3, sticky="nsew", padx=5)

fw_text = tk.Text(fw_frame)
scroll3 = tk.Scrollbar(fw_frame, command=fw_text.yview)
fw_text.config(yscrollcommand=scroll3.set)

scroll3.pack(side=tk.RIGHT, fill=tk.Y)
fw_text.pack(fill="both", expand=True)

# =========================================================
# SUPERBAN TOOL (FIXED TIMESTAMPS)
# =========================================================
def superban_tool():
    global selected_blocked_ip

    ip = extract_ip(selected_blocked_ip)

    if not ip:
        safe_log("[!] Select a valid IP")
        return

    safe_log(f"[SUPERBAN] {ip}")

    subprocess.run([
        "pkexec", "firewall-cmd",
        "--permanent",
        "--add-rich-rule=rule family=ipv4 source address=" + ip + " drop"
    ])

    subprocess.run([
        "pkexec", "firewall-cmd",
        "--permanent",
        "--add-rich-rule=rule family=ipv4 destination address=" + ip + " drop"
    ])

    subprocess.run(["pkexec", "firewall-cmd", "--reload"])

    # -----------------------------
    # FILE WRITE (FIXED)
    # -----------------------------
    os.makedirs(os.path.dirname(SUPERBAN_FILE), exist_ok=True)

    existing = {}

    if os.path.exists(SUPERBAN_FILE):
        with open(SUPERBAN_FILE) as f:
            for line in f:
                ip2, ts = parse_superban_line(line)
                if ip2:
                    existing[ip2] = ts  # save original

    existing[ip] = existing.get(ip, now_ts())

    with open(SUPERBAN_FILE, "w") as f:
        for k, v in sorted(existing.items()):
            f.write(f"{k}|{v}\n")

    update_superban()

# =========================================================
# SUPERUNBAN TOOL (FIXED - NO TOUCH TIMESTAMPS)
# =========================================================
def superunban_tool():
    global selected_superban_ip

    ip = extract_ip(selected_superban_ip)

    if not ip:
        safe_log("[!] Select a valid IP")
        return

    safe_log(f"[SUPERUNBAN] {ip}")

    subprocess.run([
        "pkexec", "firewall-cmd",
        "--permanent",
        "--remove-rich-rule=rule family=ipv4 source address=" + ip + " drop"
    ])

    subprocess.run([
        "pkexec", "firewall-cmd",
        "--permanent",
        "--remove-rich-rule=rule family=ipv4 destination address=" + ip + " drop"
    ])

    subprocess.run(["pkexec", "firewall-cmd", "--reload"])

    # -----------------------------
    # FILE CLEAN (KEEP ORIGINAL TS)
    # -----------------------------
    if os.path.exists(SUPERBAN_FILE):
        new_lines = []

        with open(SUPERBAN_FILE) as f:
            for line in f:
                ip2, ts = parse_superban_line(line)

                if ip2 and ip2 != ip:
                    if ts:
                        new_lines.append(f"{ip2}|{ts}")
                    else:
                        new_lines.append(ip2)

        with open(SUPERBAN_FILE, "w") as f:
            for x in new_lines:
                f.write(x + "\n")

    update_superban()

# -----------------------------
# BUTTONS
# -----------------------------
tk.Button(top_bar, text="SUPERBAN", bg="red", fg="white",
          command=superban_tool).pack(side=tk.LEFT, padx=5)

tk.Button(top_bar, text="SUPERUNBAN", bg="orange",
          command=superunban_tool).pack(side=tk.LEFT, padx=5)
          
tk.Button(top_bar, text="REMOVE FROM DROP ZONE", bg="purple", fg="white",
          command=remove_from_drop_zone).pack(side=tk.LEFT, padx=5)

# -----------------------------
# UPDATE BLOCKED
# -----------------------------
def update_blocked():
    global selected_blocked_ip

    current_ip = selected_blocked_ip
    blocked_listbox.delete(0, tk.END)

    restored_index = None

    try:
        if os.path.exists(BLOCK_FILE):
            with open(BLOCK_FILE) as f:
                lines = [extract_ip(x) for x in f.read().splitlines()]
                lines = [x for x in lines if x]

            for i, ip in enumerate(lines[-300:]):
                blocked_listbox.insert(tk.END, ip)

                if current_ip and ip == extract_ip(current_ip):
                    restored_index = i

        if restored_index is not None:
            blocked_listbox.selection_set(restored_index)
            blocked_listbox.activate(restored_index)
            blocked_listbox.see(restored_index)

    except Exception as e:
        safe_log(f"[ERROR BLOCK] {e}")

    root.after(REFRESH_MS, update_blocked)

# -----------------------------
# UPDATE SUPERBAN
# -----------------------------
def update_superban():
    global selected_superban_ip

    # guardar selección actual (IP)
    current_ip = selected_superban_ip

    superban_listbox.delete(0, tk.END)

    restored_index = None

    try:
        if not os.path.exists(SUPERBAN_FILE):
            superban_listbox.insert(tk.END, "No Superbanned IPs")
            return

        with open(SUPERBAN_FILE) as f:
            lines = [x.strip() for x in f if x.strip()]

        if not lines:
            superban_listbox.insert(tk.END, "No Superbanned IPs")
            return

        for i, line in enumerate(sorted(lines)):
            ip, ts = parse_superban_line(line)

            if ip:
                display = f"{ip} [{ts}]" if ts else ip
                superban_listbox.insert(tk.END, display)

                # si coincide con selección previa → guardamos índice
                if current_ip and ip == extract_ip(current_ip):
                    restored_index = i

        # restaurar highlight
        if restored_index is not None:
            superban_listbox.selection_set(restored_index)
            superban_listbox.activate(restored_index)
            superban_listbox.see(restored_index)

    except Exception as e:
        superban_listbox.insert(tk.END, f"ERROR: {e}")

    root.after(REFRESH_MS, update_superban)

# -----------------------------
# UPDATE DROP ZONE
# -----------------------------

def update_drop_zone():
    global selected_drop_ip

    current_ip = selected_drop_ip

    drop_listbox.delete(0, tk.END)

    restored_index = None

    try:
        result = subprocess.run(
            ["firewall-cmd", "--zone=drop", "--list-sources"],
            capture_output=True,
            text=True
        )

        ips = result.stdout.strip().split()

        if not ips:
            drop_listbox.insert(tk.END, "No IPs in DROP ZONE")
        else:
            for i, ip in enumerate(sorted(ips)):
                drop_listbox.insert(tk.END, ip)

                if current_ip and ip == extract_ip(current_ip):
                    restored_index = i

        # restaurar selección
        if restored_index is not None:
            drop_listbox.selection_set(restored_index)
            drop_listbox.activate(restored_index)
            drop_listbox.see(restored_index)

    except Exception as e:
        drop_listbox.insert(tk.END, f"ERROR: {e}")

    root.after(5000, update_drop_zone)
    
# -----------------------------
# FIREWALL STATUS
# -----------------------------
def update_firewall():
    try:
        r = subprocess.run(["firewall-cmd", "--list-all"],
                           capture_output=True, text=True)

        fw_text.delete("1.0", tk.END)
        fw_text.insert(tk.END, r.stdout)

    except Exception as e:
        fw_text.insert(tk.END, str(e))

    root.after(5000, update_firewall)

# -----------------------------
# OUTPUT THREAD
# -----------------------------
def read_output():
    for line in process.stdout:
        if line:
            root.after(0, log, line.strip())

# -----------------------------
# INIT
# -----------------------------
safe_log("[*] GUI started")
safe_log("The IPs in SUPERBAN are banned PERMANENTLY until manual unban. The IPs in DROP ZONE are banned automatically when a Suricata alert fires that match rules in config.json. Every time this program launches it clears the Drop Zone, then add the matching IPs from Suricata log (1 day lifespan) to Drop Zone. Superbanned IPs are added also permanent.")

update_blocked()
update_superban()
update_drop_zone()
update_firewall()

root.mainloop()
