import asyncio
import os
import socket
import struct
import sys
import threading
import json
import queue
import time
import ipaddress
import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog

# ── تنظیمات پایه ─────────────────────────────────────────────────────────────
socket.setdefaulttimeout(3.0)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ── دیتابیس CDN و امضاهای DNS ────────────────────────────────────────────────
IP_DATABASE = {
    "☁️ Cloudflare":   ["103.21.244.0/22","104.16.0.0/13","108.162.192.0/18","172.64.0.0/13","188.114.96.0/20"],
    "⚡ ArvanCloud":   ["185.143.232.0/22","94.182.160.0/19","185.176.4.0/22"],
    "🚀 Fastly":       ["151.101.0.0/16","199.232.0.0/16"],
    "📦 Amazon AWS":   ["3.5.0.0/16","52.95.0.0/16","54.239.0.0/16"],
    "🔍 Google Cloud": ["34.0.0.0/8","35.0.0.0/8"],
    "💧 DigitalOcean": ["104.131.0.0/16","138.197.0.0/16","162.243.0.0/16"],
    "🦅 Vultr":        ["108.61.0.0/16","149.28.0.0/16","207.246.64.0/18"],
    "🇩🇪 Hetzner":     ["116.202.0.0/15","135.181.0.0/16","159.69.0.0/16"],
}

DNS_SIGNATURES = {
    "amazonaws.com":       "📦 Amazon AWS",
    "digitalocean.com":    "💧 DigitalOcean",
    "vultr.com":           "🦅 Vultr",
    "hetzner.com":         "🇩🇪 Hetzner",
    "linode.com":          "🟢 Linode",
    "googleusercontent.com": "🔍 Google Cloud",
    "arvancloud":          "⚡ ArvanCloud",
    "cloudflare.com":      "☁️ Cloudflare",
    "fastly.net":          "🚀 Fastly",
}

QUALITY_THRESHOLDS = {"excellent": 150, "good": 300, "slow": 500}

def detect_provider(ip_str: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for provider, ranges in IP_DATABASE.items():
            for subnet in ranges:
                if ip_obj in ipaddress.ip_network(subnet):
                    return provider
    except ValueError:
        pass
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        hostname = hostname.lower()
        for sig, name in DNS_SIGNATURES.items():
            if sig in hostname:
                return f"{name} (DNS)"
        parts = hostname.split(".")
        short = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        return f"🌐 {short}"
    except OSError:
        return "❓ Unknown"

# ── توابع کمکی ───────────────────────────────────────────────────────────────
def get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE_PATH = os.path.join(get_exe_dir(), "debug.log")

def write_to_log_file(msg: str):
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except OSError:
        pass

def get_tcp_ping(ip: str, port: int = 443, timeout: float = 1.5) -> int:
    """TCP latency measurement (avoids ICMP restrictions)."""
    try:
        start = time.perf_counter()
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return int((time.perf_counter() - start) * 1000)
    except OSError:
        return 999

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

def quality_label(ping: int) -> str:
    if ping == 999:   return "🔴 آفلاین"
    if ping > QUALITY_THRESHOLDS["slow"]:   return "🟠 ضعیف"
    if ping > QUALITY_THRESHOLDS["good"]:   return "🟡 متوسط"
    if ping > QUALITY_THRESHOLDS["excellent"]: return "🟢 خوب"
    return "⚡ عالی"

# ── هسته TLS / SNI Spoofing ──────────────────────────────────────────────────
try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
    WINDIVERT_AVAILABLE = True
except ImportError:
    WINDIVERT_AVAILABLE = False

class ClientHelloMaker:
    _raw = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc"
        "90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8"
        "c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00"
        "160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e31001600"
        "0000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205"
        "020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e06134"
        "73e2338770efdaa98693d217001500d50000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000"
    ).replace("\n", "")
    tls_ch_template = bytes.fromhex(_raw if len(_raw) % 2 == 0 else _raw + "0")
    template_sni = b"mci.ir"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes, key_share: bytes) -> bytes:
        s1 = cls.tls_ch_template[:11]
        s3 = cls.tls_ch_template[76:120]
        s4 = cls.tls_ch_template[127 + len(cls.template_sni): 262 + len(cls.template_sni)]
        sni_len   = len(target_sni)
        sn_ext    = struct.pack("!H", sni_len + 5) + struct.pack("!H", sni_len + 3) + b"\x00" + struct.pack("!H", sni_len) + target_sni
        pad_size  = max(0, 219 - sni_len)
        pad_ext   = struct.pack("!H", pad_size) + (b"\x00" * pad_size)
        return s1 + rnd + b"\x20" + sess_id + s3 + sn_ext + s4 + key_share + b"\x00\x15" + pad_ext

# ── متغیرهای سراسری ──────────────────────────────────────────────────────────
log_queue: queue.Queue = queue.Queue()
async_loop_running     = False
fake_injective_connections: dict = {}
active_divert_ips: set = set()

LEVEL_ICONS = {
    "INFO":    "ℹ️",
    "SUCCESS": "✅",
    "ERROR":   "❌",
    "WARNING": "⚠️",
    "Scanner": "🔍",
    "DPI":     "🛡️",
    "Relay":   "⚡",
}

def gui_log(source: str, message: str, level: str = "INFO"):
    icon = LEVEL_ICONS.get(level if level in LEVEL_ICONS else source, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, source, f"{icon} {message}"))
    write_to_log_file(f"[{level}] {source}: {message}")

# ── رابط کاربری ─────────────────────────────────────────────────────────────
class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Proxy v3.6  —  TCP Scanner & DPI Bypass")
        self.geometry("1300x780")
        self.minsize(900, 600)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.server_socket: socket.socket | None = None
        self._scan_thread: threading.Thread | None = None
        self._stop_scan = threading.Event()

        self._build_sidebar()
        self._build_main_area()
        self.after(100, self._poll_logs)

    # ── sidebar ──────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=290, corner_radius=0, fg_color="#1a1a2e")
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        ctk.CTkLabel(sb, text="🛡️ SNI PROXY", font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#00d2ff").grid(row=0, column=0, padx=20, pady=(30, 4))
        ctk.CTkLabel(sb, text="TCP Scanner & DPI Bypass", font=ctk.CTkFont(size=11),
                     text_color="#888").grid(row=1, column=0, padx=20, pady=(0, 24))

        # ── Config box ──────────────────────────────────────────────────────
        box = ctk.CTkFrame(sb, fg_color="#252540", corner_radius=10)
        box.grid(row=2, column=0, padx=16, pady=4, sticky="ew")
        ctk.CTkLabel(box, text="⚙️ تنظیمات", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, columnspan=2, padx=12, pady=(10, 4), sticky="w")

        for r, (lbl, attr, placeholder) in enumerate([
            ("SNI جعلی",    "entry_sni",  "e.g. auth.vercel.com"),
            ("IP اتصال",    "entry_ip",   "e.g. 188.114.98.0"),
            ("پورت محلی",  "entry_port", "40443"),
        ], start=1):
            ctk.CTkLabel(box, text=lbl, font=ctk.CTkFont(size=11), text_color="#aaa").grid(
                row=r*2-1, column=0, padx=12, pady=(4, 0), sticky="w")
            e = ctk.CTkEntry(box, placeholder_text=placeholder, width=240)
            e.grid(row=r*2, column=0, padx=12, pady=(0, 6), sticky="ew")
            setattr(self, attr, e)

        self._load_config_to_ui()

        btn_save = ctk.CTkButton(box, text="💾 ذخیره تنظیمات", height=32,
                                 fg_color="#2980b9", hover_color="#1a5276",
                                 command=self._save_config_from_ui)
        btn_save.grid(row=7, column=0, padx=12, pady=(4, 12), sticky="ew")

        # ── action buttons ──────────────────────────────────────────────────
        self.btn_scan = ctk.CTkButton(sb, text="🔍 اسکن دامنه‌ها", height=40,
                                      fg_color="#16a085", hover_color="#0e6655",
                                      command=self._toggle_scan)
        self.btn_scan.grid(row=3, column=0, padx=16, pady=(16, 4), sticky="ew")

        btn_import = ctk.CTkButton(sb, text="📂 بارگذاری لیست SNI", height=34,
                                   fg_color="#555", hover_color="#333",
                                   command=self._import_sni_list)
        btn_import.grid(row=4, column=0, padx=16, pady=4, sticky="ew")

        btn_clear = ctk.CTkButton(sb, text="🗑️ پاک‌کردن لاگ", height=34,
                                  fg_color="#555", hover_color="#333",
                                  command=self._clear_logs)
        btn_clear.grid(row=5, column=0, padx=16, pady=4, sticky="ew")

        self.ip_lbl = ctk.CTkLabel(sb, text=f"🖥️ IP محلی:\n{get_local_ip()}",
                                   font=ctk.CTkFont(size=12, weight="bold"),
                                   text_color="#2ecc71")
        self.ip_lbl.grid(row=6, column=0, padx=20, pady=16)

        self.btn_toggle = ctk.CTkButton(sb, text="▶️ راه‌اندازی پروکسی", height=52,
                                        fg_color="#27ae60", hover_color="#1e8449",
                                        font=ctk.CTkFont(size=14, weight="bold"),
                                        command=self.toggle_proxy)
        self.btn_toggle.grid(row=7, column=0, padx=16, pady=(8, 24), sticky="sew")
        sb.grid_rowconfigure(7, weight=1)

    # ── main area ─────────────────────────────────────────────────────────────
    def _build_main_area(self):
        mw = ctk.CTkFrame(self, corner_radius=12, fg_color="#111118")
        mw.grid(row=0, column=1, padx=16, pady=16, sticky="nsew")
        mw.grid_rowconfigure(1, weight=2)
        mw.grid_rowconfigure(3, weight=1)
        mw.grid_columnconfigure(0, weight=1)

        # status bar
        self.status_bar = ctk.CTkLabel(mw, text="آماده ─ یک دامنه را اسکن کنید",
                                       font=ctk.CTkFont(size=11), text_color="#888",
                                       anchor="w")
        self.status_bar.grid(row=4, column=0, padx=20, pady=(0, 8), sticky="ew")

        # scanner table
        ctk.CTkLabel(mw, text="📊 نتایج اسکن TCP",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(16, 4), sticky="w")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background="#18181f", foreground="#ecf0f1",
                         fieldbackground="#18181f", rowheight=36,
                         font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                         background="#2d2d3d", foreground="#ccc",
                         relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#2980b9")])

        cols = ("sni", "ip", "provider", "ping", "status")
        self.scan_tree = ttk.Treeview(mw, columns=cols, show="headings", height=9)
        headers = {"sni": "دامنه (SNI)", "ip": "IP حل‌شده",
                   "provider": "زیرساخت", "ping": "تأخیر TCP", "status": "کیفیت"}
        widths  = {"sni": 230, "ip": 140, "provider": 220, "ping": 100, "status": 130}
        anchors = {"sni": "w",  "ip": "center", "provider": "w", "ping": "center", "status": "center"}
        for c in cols:
            self.scan_tree.heading(c, text=headers[c],
                                   command=lambda _c=c: self._sort_tree(_c))
            self.scan_tree.column(c, width=widths[c], anchor=anchors[c])

        vsb1 = ttk.Scrollbar(mw, orient="vertical", command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=vsb1.set)
        self.scan_tree.grid(row=1, column=0, padx=(20, 0), pady=4, sticky="nsew")
        vsb1.grid(row=1, column=1, pady=4, sticky="ns")
        self.scan_tree.bind("<<TreeviewSelect>>", self._on_item_select)
        self.scan_tree.tag_configure("excellent", foreground="#00e676")
        self.scan_tree.tag_configure("good",      foreground="#69f0ae")
        self.scan_tree.tag_configure("slow",      foreground="#ffd740")
        self.scan_tree.tag_configure("offline",   foreground="#ff5252")

        # log table
        ctk.CTkLabel(mw, text="🛠️ لاگ موتور",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=2, column=0, padx=20, pady=(12, 4), sticky="w")

        self.log_tree = ttk.Treeview(mw, columns=("T","L","S","M"), show="headings", height=7)
        self.log_tree.heading("T", text="زمان")
        self.log_tree.heading("L", text="سطح")
        self.log_tree.heading("S", text="منبع")
        self.log_tree.heading("M", text="پیام")
        self.log_tree.column("T", width=80,  anchor="center")
        self.log_tree.column("L", width=75,  anchor="center")
        self.log_tree.column("S", width=95,  anchor="center")
        self.log_tree.column("M", width=600, anchor="w")

        vsb2 = ttk.Scrollbar(mw, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=vsb2.set)
        self.log_tree.grid(row=3, column=0, padx=(20, 0), pady=(0, 4), sticky="nsew")
        vsb2.grid(row=3, column=1, pady=(0, 4), sticky="ns")

        self.log_tree.tag_configure("ERROR",   foreground="#ff5252")
        self.log_tree.tag_configure("SUCCESS", foreground="#69f0ae")
        self.log_tree.tag_configure("WARNING", foreground="#ffd740")

    # ── config helpers ────────────────────────────────────────────────────────
    def _config_path(self) -> str:
        return os.path.join(get_exe_dir(), "config.json")

    def _load_config(self) -> dict:
        try:
            with open(self._config_path()) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"LISTEN_HOST": "0.0.0.0", "LISTEN_PORT": 40443,
                    "CONNECT_IP": "188.114.98.0", "CONNECT_PORT": 443,
                    "FAKE_SNI": "auth.vercel.com"}

    def _save_config(self, cfg: dict):
        try:
            with open(self._config_path(), "w") as f:
                json.dump(cfg, f, indent=4)
        except OSError as e:
            messagebox.showerror("خطا", f"ذخیره config.json ناموفق:\n{e}")

    def _load_config_to_ui(self):
        cfg = self._load_config()
        for entry, key in [(self.entry_sni, "FAKE_SNI"),
                           (self.entry_ip,  "CONNECT_IP"),
                           (self.entry_port,"LISTEN_PORT")]:
            entry.delete(0, tk.END)
            entry.insert(0, str(cfg.get(key, "")))

    def _save_config_from_ui(self):
        cfg = self._load_config()
        sni  = self.entry_sni.get().strip()
        ip   = self.entry_ip.get().strip()
        port = self.entry_port.get().strip()
        if sni:  cfg["FAKE_SNI"]    = sni
        if ip:   cfg["CONNECT_IP"]  = ip
        if port:
            try:   cfg["LISTEN_PORT"] = int(port)
            except ValueError:
                messagebox.showwarning("خطا", "پورت باید عدد صحیح باشد.")
                return
        self._save_config(cfg)
        gui_log("Config", f"تنظیمات ذخیره شد: SNI={cfg['FAKE_SNI']} IP={cfg['CONNECT_IP']}", "SUCCESS")

    # ── scan ──────────────────────────────────────────────────────────────────
    def _toggle_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_scan.set()
            self.btn_scan.configure(text="🔍 اسکن دامنه‌ها", state="normal")
        else:
            self._stop_scan.clear()
            self.btn_scan.configure(text="⏹ توقف اسکن", fg_color="#c0392b", hover_color="#922b21")
            for i in self.scan_tree.get_children():
                self.scan_tree.delete(i)
            self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
            self._scan_thread.start()

    def _run_scan(self):
        path = os.path.join(get_exe_dir(), "sni_list.txt")
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("auth.vercel.com\ndiscord.com\ncloudflare.com\n")
        with open(path) as f:
            snis = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        gui_log("Scanner", f"شروع اسکن TCP برای {len(snis)} دامنه…", "INFO")
        self._set_status(f"در حال اسکن {len(snis)} دامنه…")

        for i, sni in enumerate(snis, 1):
            if self._stop_scan.is_set():
                break
            try:
                ip       = socket.gethostbyname(sni)
                provider = detect_provider(ip)
                ping     = get_tcp_ping(ip)
                quality  = quality_label(ping)
                ping_str = f"{ping} ms" if ping < 999 else "---"
                tag = ("excellent" if ping <= QUALITY_THRESHOLDS["excellent"] else
                       "good"      if ping <= QUALITY_THRESHOLDS["good"]      else
                       "slow"      if ping <= QUALITY_THRESHOLDS["slow"]      else
                       "offline")
                self.after(0, self._add_scan_row, sni, ip, provider, ping_str, quality, tag)
            except OSError:
                self.after(0, self._add_scan_row, sni, "ناشناخته", "—", "---", "🚫 مسدود", "offline")

            self.after(0, self._set_status, f"اسکن شد: {i}/{len(snis)}")

        gui_log("Scanner", "اسکن TCP به پایان رسید.", "SUCCESS")
        self.after(0, self._set_status, f"اسکن کامل شد — {len(snis)} دامنه بررسی شد")
        self.after(0, lambda: self.btn_scan.configure(
            text="🔍 اسکن دامنه‌ها", fg_color="#16a085", hover_color="#0e6655", state="normal"))

    def _add_scan_row(self, sni, ip, provider, ping_str, quality, tag=""):
        try:
            self.scan_tree.insert("", tk.END, values=(sni, ip, provider, ping_str, quality), tags=(tag,))
        except tk.TclError:
            pass

    def _sort_tree(self, col):
        rows = [(self.scan_tree.set(k, col), k) for k in self.scan_tree.get_children("")]
        rows.sort(key=lambda x: (x[0].replace(" ms","").strip() if x[0].replace(" ms","").strip().isdigit()
                                 else x[0].lower()))
        for i, (_, k) in enumerate(rows):
            self.scan_tree.move(k, "", i)

    def _on_item_select(self, _event):
        sel = self.scan_tree.selection()
        if not sel:
            return
        values = self.scan_tree.item(sel[0])["values"]
        sni, ip = str(values[0]), str(values[1])
        if ip in ("ناشناخته", "Unresolved"):
            return
        cfg = self._load_config()
        cfg["FAKE_SNI"]   = sni
        cfg["CONNECT_IP"] = ip
        self._save_config(cfg)
        self.entry_sni.delete(0, tk.END); self.entry_sni.insert(0, sni)
        self.entry_ip.delete(0, tk.END);  self.entry_ip.insert(0, ip)
        gui_log("Config", f"انتخاب شد: {sni}  →  {ip}", "SUCCESS")
        self._set_status(f"انتخاب شد: {sni}  ({ip})")

    def _import_sni_list(self):
        path = filedialog.askopenfilename(
            title="انتخاب فایل لیست SNI",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        dest = os.path.join(get_exe_dir(), "sni_list.txt")
        import shutil
        shutil.copy(path, dest)
        gui_log("Config", f"لیست SNI بارگذاری شد از {os.path.basename(path)}", "SUCCESS")

    def _clear_logs(self):
        for i in self.log_tree.get_children():
            self.log_tree.delete(i)

    def _set_status(self, text: str):
        self.status_bar.configure(text=text)

    # ── log poller ────────────────────────────────────────────────────────────
    def _poll_logs(self):
        while not log_queue.empty():
            t, lvl, src, msg = log_queue.get()
            tag = lvl if lvl in ("ERROR", "SUCCESS", "WARNING") else ""
            self.log_tree.insert("", 0, values=(t, lvl, src, msg), tags=(tag,))
            # keep log to 500 rows
            children = self.log_tree.get_children()
            if len(children) > 500:
                self.log_tree.delete(children[-1])
        self.after(100, self._poll_logs)

    # ── proxy ─────────────────────────────────────────────────────────────────
    def toggle_proxy(self):
        global async_loop_running, active_divert_ips
        if not async_loop_running:
            cfg = self._load_config()
            async_loop_running = True
            self.btn_toggle.configure(text="🛑 توقف پروکسی",
                                      fg_color="#e74c3c", hover_color="#c0392b")
            target_ip = cfg["CONNECT_IP"]
            local_ip  = get_local_ip()
            gui_log("System", f"پروکسی روی پورت {cfg['LISTEN_PORT']} راه‌اندازی شد", "INFO")
            threading.Thread(target=lambda: asyncio.run(self._run_srv(cfg, local_ip)),
                              daemon=True).start()

            if WINDIVERT_AVAILABLE:
                if target_ip not in active_divert_ips:
                    w_filter = (f"tcp and ((ip.SrcAddr == {local_ip} and ip.DstAddr == {target_ip})"
                                f" or (ip.SrcAddr == {target_ip} and ip.DstAddr == {local_ip}))")
                    threading.Thread(
                        target=FakeTcpInjector(w_filter, fake_injective_connections).run,
                        daemon=True).start()
                    active_divert_ips.add(target_ip)
                    gui_log("DPI", f"موتور WinDivert برای {target_ip} فعال شد", "SUCCESS")
            else:
                gui_log("DPI", "ماژول WinDivert یافت نشد! دور زدن DPI ممکن است ناقص باشد.", "WARNING")

            gui_log("System", "پروکسی آماده دریافت ترافیک است.", "SUCCESS")
            self._set_status(f"پروکسی فعال  —  {local_ip}:{cfg['LISTEN_PORT']}  →  {target_ip}")
        else:
            async_loop_running = False
            if self.server_socket:
                try: self.server_socket.close()
                except OSError: pass
            fake_injective_connections.clear()
            active_divert_ips.clear()
            self.btn_toggle.configure(text="▶️ راه‌اندازی پروکسی",
                                      fg_color="#27ae60", hover_color="#1e8449")
            gui_log("System", "پروکسی متوقف شد.", "WARNING")
            self._set_status("پروکسی متوقف شد — آماده راه‌اندازی مجدد")

    async def _run_srv(self, config: dict, _ip: str):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((config["LISTEN_HOST"], config["LISTEN_PORT"]))
            self.server_socket.listen(128)
        except OSError as e:
            gui_log("System", f"خطای bind: پورت {config['LISTEN_PORT']} احتمالاً در حال استفاده است — {e}", "ERROR")
            async_loop_running and self.after(0, self.toggle_proxy)
            return

        loop = asyncio.get_running_loop()
        while async_loop_running:
            try:
                client, addr = await loop.sock_accept(self.server_socket)
                asyncio.create_task(self._handle_client(client, addr, config))
            except OSError:
                if async_loop_running:
                    await asyncio.sleep(0.05)

    async def _handle_client(self, client: socket.socket, addr, config: dict):
        cid = f"{addr[0]}:{addr[1]}"
        gui_log("Client", f"اتصال جدید از {cid}", "INFO")
        out_sock: socket.socket | None = None
        conn = None
        try:
            loop = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((get_local_ip(), 0))

            f_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32),
                config["FAKE_SNI"].encode(), os.urandom(32))

            if WINDIVERT_AVAILABLE:
                conn = FakeInjectiveConnection(
                    out_sock, get_local_ip(), config["CONNECT_IP"],
                    out_sock.getsockname()[1], config["CONNECT_PORT"],
                    f_data, "wrong_seq", client)
                fake_injective_connections[conn.id] = conn

            await asyncio.wait_for(
                loop.sock_connect(out_sock, (config["CONNECT_IP"], config["CONNECT_PORT"])), 5)
            gui_log("Proxy", f"[{cid}] متصل شد — SNI spoofing در حال اجرا…", "SUCCESS")

            if WINDIVERT_AVAILABLE and conn:
                try:
                    await asyncio.wait_for(conn.t2a_event.wait(), 2)
                except asyncio.TimeoutError:
                    gui_log("DPI", f"[{cid}] timeout handshake — ادامه relay…", "WARNING")
                conn.monitor = False

            gui_log("Relay", f"[{cid}] تونل برقرار شد ⚡", "SUCCESS")
            task = asyncio.create_task(self._relay(out_sock, client, asyncio.current_task()))
            await self._relay(client, out_sock, task)
        except asyncio.TimeoutError:
            gui_log("Proxy", f"[{cid}] اتصال timeout شد.", "ERROR")
        except OSError as e:
            gui_log("Proxy", f"[{cid}] اتصال قطع شد: {e}", "ERROR")
        finally:
            if conn and WINDIVERT_AVAILABLE:
                fake_injective_connections.pop(conn.id, None)
            for s in (out_sock, client):
                if s:
                    try: s.close()
                    except OSError: pass

    async def _relay(self, src: socket.socket, dst: socket.socket, peer: asyncio.Task):
        loop = asyncio.get_running_loop()
        try:
            while async_loop_running:
                data = await loop.sock_recv(src, 65536)
                if not data:
                    break
                await loop.sock_sendall(dst, data)
        except OSError:
            pass
        finally:
            if peer and not peer.done():
                peer.cancel()
            try: src.close()
            except OSError: pass
            try: dst.close()
            except OSError: pass


if __name__ == "__main__":
    ModernProxyGUI().mainloop()
