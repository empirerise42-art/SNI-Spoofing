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
import tkinter.font as tkfont
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor

# ── تنظیمات پایه ──────────────────────────────────────────────────────────────
socket.setdefaulttimeout(3.0)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

SCAN_WORKERS    = 50   # تعداد thread های موازی اسکن
PING_TIMEOUT    = 1.0  # ثانیه

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
    "amazonaws.com":          "📦 Amazon AWS",
    "digitalocean.com":       "💧 DigitalOcean",
    "vultr.com":              "🦅 Vultr",
    "hetzner.com":            "🇩🇪 Hetzner",
    "linode.com":             "🟢 Linode",
    "googleusercontent.com":  "🔍 Google Cloud",
    "arvancloud":             "⚡ ArvanCloud",
    "cloudflare.com":         "☁️ Cloudflare",
    "fastly.net":             "🚀 Fastly",
}

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
        h = hostname.lower()
        for sig, name in DNS_SIGNATURES.items():
            if sig in h:
                return f"{name}"
        parts = h.split(".")
        return f"🌐 {'.'.join(parts[-2:]) if len(parts)>=2 else h}"
    except OSError:
        return "❓ ناشناخته"

def get_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE_PATH = os.path.join(get_exe_dir(), "debug.log")

def write_log(msg: str):
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} — {msg}\n")
    except OSError:
        pass

def tcp_ping(ip: str, port: int = 443) -> int:
    try:
        t = time.perf_counter()
        with socket.create_connection((ip, port), timeout=PING_TIMEOUT):
            pass
        return int((time.perf_counter() - t) * 1000)
    except OSError:
        return 999

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

def ping_tag(ping: int) -> str:
    if ping == 999:   return "offline"
    if ping > 400:    return "slow"
    if ping > 200:    return "good"
    return "excellent"

def ping_label(ping: int) -> str:
    t = ping_tag(ping)
    return {"excellent":"⚡ عالی","good":"🟢 خوب","slow":"🟡 کند","offline":"🔴 آفلاین"}[t]

# ── TLS / SNI ──────────────────────────────────────────────────────────────────
try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
    WINDIVERT_OK = True
except ImportError:
    WINDIVERT_OK = False

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
    ).replace("\n","")
    tls_ch_template = bytes.fromhex(_raw if len(_raw)%2==0 else _raw+"0")
    template_sni    = b"mci.ir"

    @classmethod
    def get_client_hello_with(cls, rnd, sess_id, target_sni, key_share):
        s1  = cls.tls_ch_template[:11]
        s3  = cls.tls_ch_template[76:120]
        s4  = cls.tls_ch_template[127+len(cls.template_sni):262+len(cls.template_sni)]
        n   = len(target_sni)
        sne = struct.pack("!H",n+5)+struct.pack("!H",n+3)+b"\x00"+struct.pack("!H",n)+target_sni
        ps  = max(0, 219-n)
        pad = struct.pack("!H",ps)+(b"\x00"*ps)
        return s1+rnd+b"\x20"+sess_id+s3+sne+s4+key_share+b"\x00\x15"+pad

# ── سراسری ──────────────────────────────────────────────────────────────────
log_queue: queue.Queue = queue.Queue()
async_loop_running     = False
fake_injective_connections: dict = {}
active_divert_ips: set = set()

def gui_log(src: str, msg: str, level: str = "INFO"):
    icons = {"INFO":"ℹ️","SUCCESS":"✅","ERROR":"❌","WARNING":"⚠️",
             "Scanner":"🔍","DPI":"🛡️","Relay":"⚡","Client":"👤","Proxy":"🔀","Config":"⚙️"}
    icon = icons.get(level if level in icons else src, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, src, f"{icon} {msg}"))
    write_log(f"[{level}] {src}: {msg}")

# ── رابط کاربری ──────────────────────────────────────────────────────────────
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Proxy  —  اسکنر TCP و دور زدن DPI")
        self.geometry("1350x820")
        self.minsize(960, 640)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.server_socket: socket.socket | None = None
        self._stop_scan   = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._scan_results: list[dict] = []   # برای کپی

        self._build_sidebar()
        self._build_main()
        self.after(100, self._poll_logs)

    # ═══════════════════════════ SIDEBAR ═════════════════════════════════════
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=300, corner_radius=0, fg_color="#12121e")
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)

        # عنوان
        ctk.CTkLabel(sb, text="🛡️ SNI PROXY",
                     font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
                     text_color="#00cfff").grid(row=0, column=0, pady=(28,2))
        ctk.CTkLabel(sb, text="دور زدن DPI  |  اسکنر TCP",
                     font=ctk.CTkFont(size=11), text_color="#556").grid(row=1, column=0, pady=(0,18))

        # ── باکس کانفیگ ──────────────────────────────────────────────────────
        box = ctk.CTkFrame(sb, fg_color="#1c1c30", corner_radius=10)
        box.grid(row=2, column=0, padx=14, pady=2, sticky="ew")
        box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(box, text="⚙️  تنظیمات اتصال",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#aaa").grid(row=0, column=0, padx=14, pady=(12,4), sticky="w")

        fields = [
            ("SNI جعلی",   "e_sni",  "hcaptcha.com",    "FAKE_SNI"),
            ("IP سرور",    "e_ip",   "104.19.229.21",   "CONNECT_IP"),
            ("پورت محلی",  "e_port", "40443",           "LISTEN_PORT"),
        ]
        self._field_map = {}
        for i,(lbl,attr,ph,key) in enumerate(fields, start=1):
            ctk.CTkLabel(box, text=lbl, font=ctk.CTkFont(size=11), text_color="#888").grid(
                row=i*2-1, column=0, padx=14, pady=(4,0), sticky="w")
            e = ctk.CTkEntry(box, placeholder_text=ph, height=32,
                             font=ctk.CTkFont(family="Consolas", size=12))
            e.grid(row=i*2, column=0, padx=14, pady=(0,4), sticky="ew")
            setattr(self, attr, e)
            self._field_map[attr] = key

        self._load_config_to_ui()

        ctk.CTkButton(box, text="💾  ذخیره تنظیمات", height=32,
                      fg_color="#1a5276", hover_color="#154360",
                      command=self._save_config_from_ui).grid(
            row=8, column=0, padx=14, pady=(4,14), sticky="ew")

        # ── دکمه‌های عملیاتی ─────────────────────────────────────────────────
        self.btn_scan = ctk.CTkButton(sb, text="🔍  شروع اسکن", height=40,
                                      fg_color="#117a65", hover_color="#0e6655",
                                      font=ctk.CTkFont(size=13, weight="bold"),
                                      command=self._toggle_scan)
        self.btn_scan.grid(row=3, column=0, padx=14, pady=(14,4), sticky="ew")

        ctk.CTkButton(sb, text="📂  بارگذاری لیست دامنه", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._import_list).grid(
            row=4, column=0, padx=14, pady=4, sticky="ew")

        ctk.CTkButton(sb, text="📋  کپی نتایج اسکن", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._copy_results).grid(
            row=5, column=0, padx=14, pady=4, sticky="ew")

        ctk.CTkButton(sb, text="💾  ذخیره نتایج (TXT)", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._export_results).grid(
            row=6, column=0, padx=14, pady=4, sticky="ew")

        ctk.CTkButton(sb, text="🗑️  پاک‌کردن لاگ", height=30,
                      fg_color="#1a1a1a", hover_color="#111",
                      command=self._clear_logs).grid(
            row=7, column=0, padx=14, pady=4, sticky="ew")

        self.lbl_ip = ctk.CTkLabel(sb, text=f"🖥️  IP شما:\n{get_local_ip()}",
                                   font=ctk.CTkFont(size=12, weight="bold"),
                                   text_color="#2ecc71")
        self.lbl_ip.grid(row=8, column=0, pady=12)

        self.btn_proxy = ctk.CTkButton(sb, text="▶️  راه‌اندازی پروکسی", height=54,
                                       fg_color="#1e8449", hover_color="#145a32",
                                       font=ctk.CTkFont(size=14, weight="bold"),
                                       command=self.toggle_proxy)
        self.btn_proxy.grid(row=9, column=0, padx=14, pady=(8,24), sticky="sew")
        sb.grid_rowconfigure(9, weight=1)

    # ═══════════════════════════ MAIN AREA ═══════════════════════════════════
    def _build_main(self):
        mw = ctk.CTkFrame(self, corner_radius=12, fg_color="#0e0e18")
        mw.grid(row=0, column=1, padx=14, pady=14, sticky="nsew")
        mw.grid_columnconfigure(0, weight=1)
        mw.grid_rowconfigure(1, weight=3)
        mw.grid_rowconfigure(3, weight=1)

        # ── جدول اسکن ────────────────────────────────────────────────────────
        hdr1 = ctk.CTkFrame(mw, fg_color="transparent")
        hdr1.grid(row=0, column=0, columnspan=2, padx=18, pady=(14,2), sticky="ew")
        hdr1.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr1, text="📊  نتایج اسکن TCP",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, sticky="w")
        self.lbl_count = ctk.CTkLabel(hdr1, text="",
                                      font=ctk.CTkFont(size=11), text_color="#888")
        self.lbl_count.grid(row=0, column=1, sticky="e")

        style = ttk.Style()
        style.theme_use("clam")
        _bg, _fg, _sel = "#141420", "#e0e0e0", "#1a5276"
        _hbg, _hfg     = "#1e1e32", "#ffffff"
        style.configure("Treeview",
                        background=_bg, foreground=_fg, fieldbackground=_bg,
                        rowheight=34, font=("Segoe UI", 10), borderwidth=0)
        style.configure("Treeview.Heading",
                        background=_hbg, foreground=_hfg,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", _sel)],
                  foreground=[("selected", "#fff")])

        cols = ("sni","ip","provider","ping","status")
        self.tree = ttk.Treeview(mw, columns=cols, show="headings",
                                 selectmode="extended")
        hdrs   = {"sni":"دامنه (SNI)","ip":"IP","provider":"زیرساخت",
                  "ping":"تأخیر","status":"کیفیت"}
        widths = {"sni":230,"ip":130,"provider":210,"ping":90,"status":110}
        anchors= {"sni":"w","ip":"center","provider":"w","ping":"center","status":"center"}
        for c in cols:
            self.tree.heading(c, text=hdrs[c],
                              command=lambda _c=c: self._sort_col(_c, False))
            self.tree.column(c, width=widths[c], anchor=anchors[c], minwidth=60)

        vsb = ttk.Scrollbar(mw, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(mw, orient="horizontal",  command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=1, column=0, padx=(18,0), pady=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns", pady=0)
        hsb.grid(row=2, column=0, sticky="ew", padx=(18,0))

        self.tree.tag_configure("excellent", foreground="#00e5ff")
        self.tree.tag_configure("good",      foreground="#69f0ae")
        self.tree.tag_configure("slow",      foreground="#ffd740")
        self.tree.tag_configure("offline",   foreground="#ff5252")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Control-c>",        lambda _: self._copy_selected())
        self.tree.bind("<Button-3>",         self._right_click)

        # ── منوی راست‌کلیک ───────────────────────────────────────────────────
        self._ctx = tk.Menu(self, tearoff=0, bg="#1e1e2e", fg="white",
                            activebackground="#2980b9", activeforeground="white",
                            font=("Segoe UI", 10))
        self._ctx.add_command(label="✅  انتخاب به عنوان پروکسی",  command=self._ctx_select)
        self._ctx.add_command(label="📋  کپی ردیف انتخابی",         command=self._copy_selected)
        self._ctx.add_command(label="📋  کپی فقط دامنه‌ها",          command=self._copy_domains)
        self._ctx.add_command(label="📋  کپی فقط IP‌ها",             command=self._copy_ips)
        self._ctx.add_separator()
        self._ctx.add_command(label="🗑️  حذف ردیف‌های آفلاین",       command=self._remove_offline)

        # ── لاگ ──────────────────────────────────────────────────────────────
        ctk.CTkLabel(mw, text="🛠️  لاگ موتور",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=3, column=0, padx=18, pady=(8,2), sticky="w", columnspan=2)

        self.log_tree = ttk.Treeview(mw, columns=("T","L","S","M"),
                                     show="headings", height=6)
        self.log_tree.heading("T", text="زمان")
        self.log_tree.heading("L", text="سطح")
        self.log_tree.heading("S", text="منبع")
        self.log_tree.heading("M", text="پیام")
        self.log_tree.column("T", width=75,  anchor="center")
        self.log_tree.column("L", width=70,  anchor="center")
        self.log_tree.column("S", width=85,  anchor="center")
        self.log_tree.column("M", width=700, anchor="w")

        lvsb = ttk.Scrollbar(mw, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=lvsb.set)
        self.log_tree.grid(row=4, column=0, padx=(18,0), pady=(0,4), sticky="nsew")
        lvsb.grid(row=4, column=1, pady=(0,4), sticky="ns")

        self.log_tree.tag_configure("ERROR",   foreground="#ff5252")
        self.log_tree.tag_configure("SUCCESS", foreground="#69f0ae")
        self.log_tree.tag_configure("WARNING", foreground="#ffd740")
        mw.grid_rowconfigure(4, weight=1)

        # ── نوار وضعیت ───────────────────────────────────────────────────────
        self.lbl_status = ctk.CTkLabel(mw, text="آماده ─ روی «شروع اسکن» کلیک کنید",
                                       font=ctk.CTkFont(size=11), text_color="#556",
                                       anchor="w")
        self.lbl_status.grid(row=5, column=0, columnspan=2, padx=18, pady=(0,8), sticky="ew")

    # ═══════════════════════════ CONFIG ══════════════════════════════════════
    def _cfg_path(self): return os.path.join(get_exe_dir(), "config.json")

    def _load_cfg(self) -> dict:
        defaults = {"LISTEN_HOST":"0.0.0.0","LISTEN_PORT":40443,
                    "CONNECT_IP":"104.19.229.21","CONNECT_PORT":443,
                    "FAKE_SNI":"hcaptcha.com"}
        try:
            with open(self._cfg_path()) as f:
                return {**defaults, **json.load(f)}
        except (OSError, json.JSONDecodeError):
            return defaults

    def _save_cfg(self, cfg: dict):
        try:
            with open(self._cfg_path(), "w") as f:
                json.dump(cfg, f, indent=4)
        except OSError as e:
            messagebox.showerror("خطا", f"ذخیره config.json ناموفق:\n{e}")

    def _load_config_to_ui(self):
        cfg = self._load_cfg()
        for attr, key in [("e_sni","FAKE_SNI"),("e_ip","CONNECT_IP"),("e_port","LISTEN_PORT")]:
            w = getattr(self, attr)
            w.delete(0, tk.END)
            w.insert(0, str(cfg.get(key,"")))

    def _save_config_from_ui(self):
        cfg = self._load_cfg()
        sni  = self.e_sni.get().strip()
        ip   = self.e_ip.get().strip()
        port = self.e_port.get().strip()
        if sni:  cfg["FAKE_SNI"]   = sni
        if ip:   cfg["CONNECT_IP"] = ip
        if port:
            try:   cfg["LISTEN_PORT"] = int(port)
            except ValueError:
                messagebox.showwarning("خطا", "پورت باید عدد باشد"); return
        self._save_cfg(cfg)
        gui_log("Config", f"ذخیره شد ← SNI={cfg['FAKE_SNI']}  IP={cfg['CONNECT_IP']}", "SUCCESS")

    # ═══════════════════════════ SCAN ════════════════════════════════════════
    def _toggle_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_scan.set()
            self.btn_scan.configure(text="🔍  شروع اسکن",
                                    fg_color="#117a65", hover_color="#0e6655")
        else:
            self._stop_scan.clear()
            self._scan_results.clear()
            for i in self.tree.get_children(): self.tree.delete(i)
            self.lbl_count.configure(text="")
            self.btn_scan.configure(text="⏹  توقف اسکن",
                                    fg_color="#922b21", hover_color="#7b241c")
            self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
            self._scan_thread.start()

    def _run_scan(self):
        path = os.path.join(get_exe_dir(), "sni_list.txt")
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("hcaptcha.com\ndiscord.com\ncloudflare.com\n")

        with open(path, encoding="utf-8", errors="ignore") as f:
            snis = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        total = len(snis)
        gui_log("Scanner", f"اسکن موازی {total} دامنه با {SCAN_WORKERS} thread…", "INFO")
        self._set_status(f"در حال اسکن {total} دامنه…")

        done   = [0]
        lock   = threading.Lock()

        def scan_one(sni):
            if self._stop_scan.is_set():
                return
            try:
                ip       = socket.gethostbyname(sni)
                provider = detect_provider(ip)
                ping     = tcp_ping(ip)
            except OSError:
                ip, provider, ping = "خطا", "—", 999

            tag      = ping_tag(ping)
            qlabel   = ping_label(ping)
            ping_str = f"{ping} ms" if ping < 999 else "---"
            row      = {"sni":sni,"ip":ip,"provider":provider,
                        "ping":ping,"ping_str":ping_str,"quality":qlabel,"tag":tag}

            with lock:
                self._scan_results.append(row)
                done[0] += 1
                d = done[0]

            self.after(0, self._add_row, sni, ip, provider, ping_str, qlabel, tag)
            if d % 10 == 0 or d == total:
                self.after(0, self._set_status,
                           f"اسکن شد: {d} / {total}  —  فشار دهید Ctrl+C برای کپی")
                self.after(0, self.lbl_count.configure,
                           {"text": f"{d} / {total}"})

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            ex.map(scan_one, snis)

        gui_log("Scanner", f"اسکن کامل شد — {total} دامنه بررسی شد.", "SUCCESS")
        self.after(0, self._set_status,
                   f"✅ اسکن کامل — {total} دامنه  |  کلیک راست برای گزینه‌ها")
        self.after(0, self.lbl_count.configure, {"text": f"{total} / {total}"})
        self.after(0, self.btn_scan.configure,
                   {"text":"🔍  شروع اسکن","fg_color":"#117a65","hover_color":"#0e6655"})

    def _add_row(self, sni, ip, provider, ping_str, quality, tag):
        try:
            self.tree.insert("", tk.END,
                             values=(sni, ip, provider, ping_str, quality),
                             tags=(tag,))
        except tk.TclError:
            pass

    def _sort_col(self, col, reverse):
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            rows.sort(key=lambda x: int(x[0].replace(" ms","").strip()), reverse=reverse)
        except ValueError:
            rows.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)
        self.tree.heading(col, command=lambda: self._sort_col(col, not reverse))

    # ═══════════════════════════ SELECTION / COPY ════════════════════════════
    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        sni, ip = str(vals[0]), str(vals[1])
        if ip in ("خطا","Unresolved"): return
        cfg = self._load_cfg()
        cfg["FAKE_SNI"] = sni; cfg["CONNECT_IP"] = ip
        self._save_cfg(cfg)
        for attr, val in [("e_sni",sni),("e_ip",ip)]:
            w = getattr(self, attr)
            w.delete(0, tk.END); w.insert(0, val)
        gui_log("Config", f"انتخاب: {sni}  →  {ip}", "SUCCESS")
        self._set_status(f"انتخاب شد: {sni}  ({ip})")

    def _ctx_select(self): self._on_select()

    def _right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row: self.tree.selection_set(row)
        self._ctx.post(event.x_root, event.y_root)

    def _selected_values(self):
        sel = self.tree.selection()
        if not sel:
            sel = self.tree.get_children()
        return [self.tree.item(k)["values"] for k in sel]

    def _copy_selected(self):
        rows = self._selected_values()
        text = "\n".join(
            f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}" for r in rows)
        self._to_clipboard(text)
        gui_log("Config", f"{len(rows)} ردیف کپی شد.", "SUCCESS")

    def _copy_domains(self):
        rows = self._selected_values()
        self._to_clipboard("\n".join(str(r[0]) for r in rows))
        gui_log("Config", f"{len(rows)} دامنه کپی شد.", "SUCCESS")

    def _copy_ips(self):
        rows = self._selected_values()
        self._to_clipboard("\n".join(str(r[1]) for r in rows if str(r[1]) not in ("خطا","")))
        gui_log("Config", f"{len(rows)} IP کپی شد.", "SUCCESS")

    def _copy_results(self):
        if not self._scan_results:
            messagebox.showinfo("کپی", "هنوز نتیجه‌ای وجود ندارد."); return
        header = "دامنه\tIP\tزیرساخت\tتأخیر\tکیفیت"
        lines  = [header] + [
            f"{r['sni']}\t{r['ip']}\t{r['provider']}\t{r['ping_str']}\t{r['quality']}"
            for r in self._scan_results]
        self._to_clipboard("\n".join(lines))
        gui_log("Config", f"همه {len(self._scan_results)} نتیجه کپی شد.", "SUCCESS")

    def _export_results(self):
        if not self._scan_results:
            messagebox.showinfo("ذخیره", "هنوز نتیجه‌ای وجود ندارد."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file","*.txt"),("All","*.*")],
            title="ذخیره نتایج اسکن")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write("دامنه\tIP\tزیرساخت\tتأخیر\tکیفیت\n")
            for r in self._scan_results:
                f.write(f"{r['sni']}\t{r['ip']}\t{r['provider']}\t{r['ping_str']}\t{r['quality']}\n")
        gui_log("Config", f"نتایج در {os.path.basename(path)} ذخیره شد.", "SUCCESS")

    def _remove_offline(self):
        removed = 0
        for k in self.tree.get_children():
            if "آفلاین" in str(self.tree.item(k)["values"]):
                self.tree.delete(k); removed += 1
        gui_log("Scanner", f"{removed} ردیف آفلاین حذف شد.", "INFO")

    def _to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def _import_list(self):
        path = filedialog.askopenfilename(
            title="انتخاب فایل لیست دامنه",
            filetypes=[("Text","*.txt"),("All","*.*")])
        if not path: return
        import shutil
        shutil.copy(path, os.path.join(get_exe_dir(), "sni_list.txt"))
        gui_log("Config", f"لیست بارگذاری شد: {os.path.basename(path)}", "SUCCESS")

    def _clear_logs(self):
        for i in self.log_tree.get_children(): self.log_tree.delete(i)

    def _set_status(self, t: str):
        self.lbl_status.configure(text=t)

    # ═══════════════════════════ LOG POLLER ══════════════════════════════════
    def _poll_logs(self):
        try:
            while not log_queue.empty():
                t, lvl, src, msg = log_queue.get_nowait()
                tag = lvl if lvl in ("ERROR","SUCCESS","WARNING") else ""
                self.log_tree.insert("", 0, values=(t,lvl,src,msg), tags=(tag,))
                ch = self.log_tree.get_children()
                if len(ch) > 600: self.log_tree.delete(ch[-1])
        except queue.Empty:
            pass
        self.after(80, self._poll_logs)

    # ═══════════════════════════ PROXY ═══════════════════════════════════════
    def toggle_proxy(self):
        global async_loop_running, active_divert_ips
        if not async_loop_running:
            cfg      = self._load_cfg()
            local_ip = get_local_ip()
            async_loop_running = True
            self.btn_proxy.configure(text="🛑  توقف پروکسی",
                                     fg_color="#922b21", hover_color="#7b241c")
            threading.Thread(
                target=lambda: asyncio.run(self._run_srv(cfg, local_ip)),
                daemon=True).start()

            if WINDIVERT_OK:
                tgt = cfg["CONNECT_IP"]
                if tgt not in active_divert_ips:
                    wf = (f"tcp and ((ip.SrcAddr=={local_ip} and ip.DstAddr=={tgt})"
                          f" or (ip.SrcAddr=={tgt} and ip.DstAddr=={local_ip}))")
                    threading.Thread(
                        target=FakeTcpInjector(wf, fake_injective_connections).run,
                        daemon=True).start()
                    active_divert_ips.add(tgt)
                    gui_log("DPI", f"WinDivert فعال برای {tgt}", "SUCCESS")
            else:
                gui_log("DPI", "WinDivert یافت نشد — DPI bypass ناقص است.", "WARNING")

            gui_log("System", f"پروکسی روی {local_ip}:{cfg['LISTEN_PORT']} فعال شد.", "SUCCESS")
            self._set_status(f"پروکسی فعال  ─  {local_ip}:{cfg['LISTEN_PORT']}  →  {cfg['CONNECT_IP']}")
        else:
            async_loop_running = False
            if self.server_socket:
                try: self.server_socket.close()
                except: pass
            fake_injective_connections.clear()
            active_divert_ips.clear()
            self.btn_proxy.configure(text="▶️  راه‌اندازی پروکسی",
                                     fg_color="#1e8449", hover_color="#145a32")
            gui_log("System", "پروکسی متوقف شد.", "WARNING")
            self._set_status("پروکسی متوقف شد — آماده راه‌اندازی مجدد")

    async def _run_srv(self, config, _):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((config["LISTEN_HOST"], config["LISTEN_PORT"]))
            self.server_socket.listen(256)
        except OSError as e:
            gui_log("System", f"خطای bind: پورت {config['LISTEN_PORT']} احتمالاً در استفاده است — {e}", "ERROR")
            return
        loop = asyncio.get_running_loop()
        while async_loop_running:
            try:
                client, addr = await loop.sock_accept(self.server_socket)
                asyncio.create_task(self._handle(client, addr, config))
            except OSError:
                if async_loop_running: await asyncio.sleep(0.05)

    async def _handle(self, client, addr, cfg):
        cid = f"{addr[0]}:{addr[1]}"
        out_sock = conn = None
        try:
            loop     = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((get_local_ip(), 0))
            f_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32),
                cfg["FAKE_SNI"].encode(), os.urandom(32))
            if WINDIVERT_OK:
                conn = FakeInjectiveConnection(
                    out_sock, get_local_ip(), cfg["CONNECT_IP"],
                    out_sock.getsockname()[1], cfg["CONNECT_PORT"],
                    f_data, "wrong_seq", client)
                fake_injective_connections[conn.id] = conn
            await asyncio.wait_for(
                loop.sock_connect(out_sock, (cfg["CONNECT_IP"], cfg["CONNECT_PORT"])), 5)
            if WINDIVERT_OK and conn:
                try:    await asyncio.wait_for(conn.t2a_event.wait(), 2)
                except asyncio.TimeoutError: pass
                conn.monitor = False
            gui_log("Relay", f"[{cid}] تونل برقرار ⚡", "SUCCESS")
            task = asyncio.create_task(self._relay(out_sock, client, asyncio.current_task()))
            await self._relay(client, out_sock, task)
        except (asyncio.TimeoutError, OSError) as e:
            gui_log("Proxy", f"[{cid}] قطع: {e}", "ERROR")
        finally:
            if conn and WINDIVERT_OK:
                fake_injective_connections.pop(conn.id, None)
            for s in (out_sock, client):
                if s:
                    try: s.close()
                    except: pass

    async def _relay(self, src, dst, peer):
        loop = asyncio.get_running_loop()
        try:
            while async_loop_running:
                data = await loop.sock_recv(src, 65536)
                if not data: break
                await loop.sock_sendall(dst, data)
        except OSError: pass
        finally:
            if peer and not peer.done(): peer.cancel()
            for s in (src, dst):
                try: s.close()
                except: pass


if __name__ == "__main__":
    App().mainloop()
