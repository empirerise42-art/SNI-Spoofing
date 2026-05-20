import asyncio
from typing import Optional
import os
import socket
import struct
import ssl
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
socket.setdefaulttimeout(2.0)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

SCAN_WORKERS    = 60
PING_TIMEOUT    = 2.0   # 2 ثانیه تایم‌اوت
SCAN_TIMEOUT    = 2.0

# ── رنج‌های کامل Cloudflare (به‌روزشده) ─────────────────────────────────────
CLOUDFLARE_RANGES = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "104.16.0.0/13","104.24.0.0/14",
    "108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
    "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20",
    "188.114.96.0/20","190.93.240.0/20","197.234.240.0/22",
    "198.41.128.0/17",
]

IP_DATABASE = {
    "☁️ Cloudflare":   CLOUDFLARE_RANGES,
    "⚡ ArvanCloud":   ["185.143.232.0/22","94.182.160.0/19","185.176.4.0/22","82.99.192.0/19"],
    "🚀 Fastly":       ["151.101.0.0/16","199.232.0.0/16","23.235.32.0/20"],
    "📦 Amazon AWS":   ["3.5.0.0/16","52.95.0.0/16","54.239.0.0/16","52.0.0.0/11"],
    "🔍 Google Cloud": ["34.0.0.0/8","35.0.0.0/8","130.211.0.0/22","142.250.0.0/15"],
    "💧 DigitalOcean": ["104.131.0.0/16","138.197.0.0/16","162.243.0.0/16","167.99.0.0/16"],
    "🦅 Vultr":        ["108.61.0.0/16","149.28.0.0/16","207.246.64.0/18","45.63.0.0/16"],
    "🇩🇪 Hetzner":     ["116.202.0.0/15","135.181.0.0/16","159.69.0.0/16","95.216.0.0/16"],
    "🟢 Linode":       ["45.33.0.0/17","45.56.0.0/21","45.79.0.0/16","96.126.96.0/20"],
    "🔵 Microsoft":    ["13.64.0.0/11","20.0.0.0/8","40.64.0.0/10"],
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
    "cloudflare.net":         "☁️ Cloudflare",
    "fastly.net":             "🚀 Fastly",
    "microsoft.com":          "🔵 Microsoft",
    "azure.com":              "🔵 Microsoft",
}

_cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES]

def is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in _cf_networks)
    except ValueError:
        return False

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
                return name
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
    """پینگ TCP با تایم‌اوت 2 ثانیه"""
    try:
        t = time.perf_counter()
        with socket.create_connection((ip, port), timeout=PING_TIMEOUT):
            pass
        return int((time.perf_counter() - t) * 1000)
    except OSError:
        return 9999

def tls_handshake_check(ip: str, sni: str, port: int = 443) -> dict:
    """بررسی TLS handshake واقعی — اطلاعات گواهی + ALPN"""
    result = {"tls": False, "cert_cn": "", "alpn": "", "tls_ver": "", "cdn_header": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((ip, port), timeout=SCAN_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                result["tls"]     = True
                result["tls_ver"] = s.version() or ""
                result["alpn"]    = s.selected_alpn_protocol() or ""
                cert              = s.getpeercert(binary_form=False)
                if cert:
                    for field in cert.get("subject", []):
                        for k, v in field:
                            if k == "commonName":
                                result["cert_cn"] = v
                                break
    except Exception:
        pass
    return result

def http_probe(ip: str, sni: str, port: int = 443) -> str:
    """بررسی HTTP header برای تشخیص CDN"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=SCAN_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                req = (f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
                       "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                s.sendall(req.encode())
                resp = b""
                while len(resp) < 4096:
                    chunk = s.recv(512)
                    if not chunk: break
                    resp += chunk
                headers = resp.decode(errors="ignore").lower()
                if "cf-ray" in headers or "cloudflare" in headers:
                    return "☁️ CF-Ray ✓"
                if "x-served-by" in headers and "fastly" in headers:
                    return "🚀 Fastly ✓"
                if "x-cache" in headers:
                    return "🔀 Cache ✓"
                return ""
    except Exception:
        return ""

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

def ping_tag(ping: int) -> str:
    if ping >= 9999:  return "offline"
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
        self.title("SNI Proxy  —  اسکنر حرفه‌ای TCP / TLS  |  کلادفلر")
        self.geometry("1500x880")
        self.minsize(1100, 680)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.server_socket: object = None
        self._stop_scan   = threading.Event()
        self._scan_thread: object = None
        self._scan_results: list[dict] = []
        self._cf_only_mode = tk.BooleanVar(value=False)
        self._deep_scan    = tk.BooleanVar(value=True)

        self._build_sidebar()
        self._build_main()
        self.after(100, self._poll_logs)

    # ═══════════════════════════ SIDEBAR ═════════════════════════════════════
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=310, corner_radius=0, fg_color="#12121e")
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(sb, text="🛡️ SNI PROXY",
                     font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
                     text_color="#00cfff").grid(row=0, column=0, pady=(24,2))
        ctk.CTkLabel(sb, text="اسکنر حرفه‌ای  |  دور زدن DPI",
                     font=ctk.CTkFont(size=11), text_color="#556").grid(row=1, column=0, pady=(0,12))

        # ── باکس کانفیگ ──────────────────────────────────────────────────────
        box = ctk.CTkFrame(sb, fg_color="#1c1c30", corner_radius=10)
        box.grid(row=2, column=0, padx=12, pady=2, sticky="ew")
        box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(box, text="⚙️  تنظیمات اتصال",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#aaa").grid(row=0, column=0, padx=12, pady=(10,4), sticky="w")

        # SNI دستی با دکمه کپی/پیست
        ctk.CTkLabel(box, text="SNI جعلی (دستی کپی‌پیست)", font=ctk.CTkFont(size=11),
                     text_color="#888").grid(row=1, column=0, padx=12, pady=(4,0), sticky="w")
        sni_row = ctk.CTkFrame(box, fg_color="transparent")
        sni_row.grid(row=2, column=0, padx=12, pady=(0,4), sticky="ew")
        sni_row.grid_columnconfigure(0, weight=1)
        self.e_sni = ctk.CTkEntry(sni_row, placeholder_text="hcaptcha.com", height=32,
                                   font=ctk.CTkFont(family="Consolas", size=12))
        self.e_sni.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(sni_row, text="📋", width=32, height=32,
                      command=self._paste_sni).grid(row=0, column=1, padx=(4,0))

        ctk.CTkLabel(box, text="IP سرور", font=ctk.CTkFont(size=11),
                     text_color="#888").grid(row=3, column=0, padx=12, pady=(4,0), sticky="w")
        ip_row = ctk.CTkFrame(box, fg_color="transparent")
        ip_row.grid(row=4, column=0, padx=12, pady=(0,4), sticky="ew")
        ip_row.grid_columnconfigure(0, weight=1)
        self.e_ip = ctk.CTkEntry(ip_row, placeholder_text="104.19.229.21", height=32,
                                  font=ctk.CTkFont(family="Consolas", size=12))
        self.e_ip.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(ip_row, text="📋", width=32, height=32,
                      command=self._paste_ip).grid(row=0, column=1, padx=(4,0))

        ctk.CTkLabel(box, text="پورت محلی", font=ctk.CTkFont(size=11),
                     text_color="#888").grid(row=5, column=0, padx=12, pady=(4,0), sticky="w")
        self.e_port = ctk.CTkEntry(box, placeholder_text="40443", height=32,
                                    font=ctk.CTkFont(family="Consolas", size=12))
        self.e_port.grid(row=6, column=0, padx=12, pady=(0,4), sticky="ew")

        self._load_config_to_ui()

        ctk.CTkButton(box, text="💾  ذخیره تنظیمات", height=32,
                      fg_color="#1a5276", hover_color="#154360",
                      command=self._save_config_from_ui).grid(
            row=7, column=0, padx=12, pady=(4,12), sticky="ew")

        # ── گزینه‌های اسکن ───────────────────────────────────────────────────
        opt_box = ctk.CTkFrame(sb, fg_color="#1c1c30", corner_radius=10)
        opt_box.grid(row=3, column=0, padx=12, pady=6, sticky="ew")
        opt_box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(opt_box, text="🔧  گزینه‌های اسکن",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#aaa").grid(row=0, column=0, padx=12, pady=(8,4), sticky="w")

        ctk.CTkCheckBox(opt_box, text="فقط کلادفلر نمایش بده",
                        variable=self._cf_only_mode,
                        font=ctk.CTkFont(size=11)).grid(
            row=1, column=0, padx=12, pady=2, sticky="w")
        ctk.CTkCheckBox(opt_box, text="اسکن عمیق TLS + HTTP (دقیق‌تر)",
                        variable=self._deep_scan,
                        font=ctk.CTkFont(size=11)).grid(
            row=2, column=0, padx=12, pady=(2,10), sticky="w")

        # ── دکمه‌های عملیاتی ─────────────────────────────────────────────────
        self.btn_scan = ctk.CTkButton(sb, text="🔍  شروع اسکن", height=42,
                                      fg_color="#117a65", hover_color="#0e6655",
                                      font=ctk.CTkFont(size=13, weight="bold"),
                                      command=self._toggle_scan)
        self.btn_scan.grid(row=4, column=0, padx=12, pady=(8,4), sticky="ew")

        ctk.CTkButton(sb, text="☁️  فقط کلادفلر (مرتب‌شده)", height=34,
                      fg_color="#1a3a5c", hover_color="#0f2540",
                      command=self._show_cf_sorted).grid(
            row=5, column=0, padx=12, pady=3, sticky="ew")

        ctk.CTkButton(sb, text="📂  بارگذاری لیست دامنه", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._import_list).grid(
            row=6, column=0, padx=12, pady=3, sticky="ew")

        ctk.CTkButton(sb, text="📋  کپی نتایج اسکن", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._copy_results).grid(
            row=7, column=0, padx=12, pady=3, sticky="ew")

        ctk.CTkButton(sb, text="💾  ذخیره نتایج (TXT)", height=34,
                      fg_color="#2c3e50", hover_color="#1a252f",
                      command=self._export_results).grid(
            row=8, column=0, padx=12, pady=3, sticky="ew")

        ctk.CTkButton(sb, text="🗑️  پاک‌کردن لاگ", height=30,
                      fg_color="#1a1a1a", hover_color="#111",
                      command=self._clear_logs).grid(
            row=9, column=0, padx=12, pady=3, sticky="ew")

        self.lbl_ip = ctk.CTkLabel(sb, text=f"🖥️  IP شما:\n{get_local_ip()}",
                                   font=ctk.CTkFont(size=12, weight="bold"),
                                   text_color="#2ecc71")
        self.lbl_ip.grid(row=10, column=0, pady=8)

        self.btn_proxy = ctk.CTkButton(sb, text="▶️  راه‌اندازی پروکسی", height=54,
                                       fg_color="#1e8449", hover_color="#145a32",
                                       font=ctk.CTkFont(size=14, weight="bold"),
                                       command=self.toggle_proxy)
        self.btn_proxy.grid(row=11, column=0, padx=12, pady=(8,20), sticky="sew")
        sb.grid_rowconfigure(11, weight=1)

    # ═══════════════════════════ MAIN AREA ═══════════════════════════════════
    def _build_main(self):
        mw = ctk.CTkFrame(self, corner_radius=12, fg_color="#0e0e18")
        mw.grid(row=0, column=1, padx=14, pady=14, sticky="nsew")
        mw.grid_columnconfigure(0, weight=1)
        mw.grid_rowconfigure(1, weight=3)
        mw.grid_rowconfigure(4, weight=1)

        # ── هدر جدول ─────────────────────────────────────────────────────────
        hdr1 = ctk.CTkFrame(mw, fg_color="transparent")
        hdr1.grid(row=0, column=0, columnspan=2, padx=18, pady=(14,2), sticky="ew")
        hdr1.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hdr1, text="📊  نتایج اسکن حرفه‌ای TCP/TLS",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, sticky="w")
        self.lbl_count = ctk.CTkLabel(hdr1, text="",
                                      font=ctk.CTkFont(size=11), text_color="#888")
        self.lbl_count.grid(row=0, column=2, sticky="e")

        # ── نوار فیلتر ───────────────────────────────────────────────────────
        filter_row = ctk.CTkFrame(mw, fg_color="transparent")
        filter_row.grid(row=0, column=0, columnspan=2, padx=18, pady=(38,2), sticky="ew")
        ctk.CTkLabel(filter_row, text="🔎 فیلتر:",
                     font=ctk.CTkFont(size=11)).grid(row=0, column=0, padx=(0,4))
        self.e_filter = ctk.CTkEntry(filter_row, placeholder_text="نام دامنه، IP، یا زیرساخت...",
                                      height=26, width=260, font=ctk.CTkFont(size=11))
        self.e_filter.grid(row=0, column=1)
        self.e_filter.bind("<KeyRelease>", self._apply_filter)

        # ── جدول اسکن ────────────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        _bg, _fg, _sel = "#141420", "#e0e0e0", "#1a5276"
        _hbg, _hfg     = "#1e1e32", "#ffffff"
        style.configure("Treeview",
                        background=_bg, foreground=_fg, fieldbackground=_bg,
                        rowheight=30, font=("Segoe UI", 10), borderwidth=0)
        style.configure("Treeview.Heading",
                        background=_hbg, foreground=_hfg,
                        relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", _sel)],
                  foreground=[("selected", "#fff")])

        cols = ("sni","ip","provider","ping","status","tls","alpn","cert","cdn_sig")
        self.tree = ttk.Treeview(mw, columns=cols, show="headings",
                                 selectmode="extended")
        hdrs   = {"sni":"دامنه (SNI)","ip":"IP","provider":"زیرساخت",
                  "ping":"پینگ ms","status":"کیفیت",
                  "tls":"TLS","alpn":"ALPN","cert":"گواهی CN","cdn_sig":"امضای CDN"}
        widths = {"sni":200,"ip":125,"provider":180,"ping":80,"status":90,
                  "tls":55,"alpn":65,"cert":170,"cdn_sig":110}
        anchors= {"sni":"w","ip":"center","provider":"w","ping":"center",
                  "status":"center","tls":"center","alpn":"center","cert":"w","cdn_sig":"center"}
        for c in cols:
            self.tree.heading(c, text=hdrs[c],
                              command=lambda _c=c: self._sort_col(_c, False))
            self.tree.column(c, width=widths[c], anchor=anchors[c], minwidth=50)

        vsb = ttk.Scrollbar(mw, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(mw, orient="horizontal",  command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=1, column=0, padx=(18,0), pady=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew", padx=(18,0))

        self.tree.tag_configure("excellent",  foreground="#00e5ff")
        self.tree.tag_configure("good",       foreground="#69f0ae")
        self.tree.tag_configure("slow",       foreground="#ffd740")
        self.tree.tag_configure("offline",    foreground="#ff5252")
        self.tree.tag_configure("cf_online",  foreground="#00cfff", background="#0a1520")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Control-c>",         lambda _: self._copy_selected())
        self.tree.bind("<Button-3>",          self._right_click)

        # ── منوی راست‌کلیک ───────────────────────────────────────────────────
        self._ctx = tk.Menu(self, tearoff=0, bg="#1e1e2e", fg="white",
                            activebackground="#2980b9", activeforeground="white",
                            font=("Segoe UI", 10))
        self._ctx.add_command(label="✅  انتخاب به عنوان پروکسی",  command=self._ctx_select)
        self._ctx.add_command(label="📋  کپی ردیف انتخابی",         command=self._copy_selected)
        self._ctx.add_command(label="📋  کپی فقط دامنه‌ها",          command=self._copy_domains)
        self._ctx.add_command(label="📋  کپی فقط IP‌ها",             command=self._copy_ips)
        self._ctx.add_separator()
        self._ctx.add_command(label="☁️  نمایش فقط کلادفلر",         command=self._show_cf_sorted)
        self._ctx.add_command(label="🗑️  حذف ردیف‌های آفلاین",       command=self._remove_offline)

        # ── خلاصه آماری ──────────────────────────────────────────────────────
        self.lbl_stats = ctk.CTkLabel(mw, text="",
                                      font=ctk.CTkFont(size=11), text_color="#2ecc71",
                                      anchor="w")
        self.lbl_stats.grid(row=3, column=0, columnspan=2, padx=18, pady=(4,0), sticky="ew")

        # ── لاگ ──────────────────────────────────────────────────────────────
        ctk.CTkLabel(mw, text="🛠️  لاگ موتور",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=4, column=0, padx=18, pady=(6,2), sticky="w", columnspan=2)

        self.log_tree = ttk.Treeview(mw, columns=("T","L","S","M"),
                                     show="headings", height=5)
        self.log_tree.heading("T", text="زمان")
        self.log_tree.heading("L", text="سطح")
        self.log_tree.heading("S", text="منبع")
        self.log_tree.heading("M", text="پیام")
        self.log_tree.column("T", width=75,  anchor="center")
        self.log_tree.column("L", width=70,  anchor="center")
        self.log_tree.column("S", width=85,  anchor="center")
        self.log_tree.column("M", width=800, anchor="w")

        lvsb = ttk.Scrollbar(mw, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=lvsb.set)
        self.log_tree.grid(row=5, column=0, padx=(18,0), pady=(0,4), sticky="nsew")
        lvsb.grid(row=5, column=1, pady=(0,4), sticky="ns")

        self.log_tree.tag_configure("ERROR",   foreground="#ff5252")
        self.log_tree.tag_configure("SUCCESS", foreground="#69f0ae")
        self.log_tree.tag_configure("WARNING", foreground="#ffd740")
        mw.grid_rowconfigure(5, weight=1)

        # ── نوار وضعیت ───────────────────────────────────────────────────────
        self.lbl_status = ctk.CTkLabel(mw, text="آماده ─ روی «شروع اسکن» کلیک کنید",
                                       font=ctk.CTkFont(size=11), text_color="#556",
                                       anchor="w")
        self.lbl_status.grid(row=6, column=0, columnspan=2, padx=18, pady=(0,8), sticky="ew")

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

    def _paste_sni(self):
        try:
            txt = self.clipboard_get().strip()
            self.e_sni.delete(0, tk.END)
            self.e_sni.insert(0, txt)
        except Exception:
            pass

    def _paste_ip(self):
        try:
            txt = self.clipboard_get().strip()
            self.e_ip.delete(0, tk.END)
            self.e_ip.insert(0, txt)
        except Exception:
            pass

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
            self.lbl_stats.configure(text="")
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

        total      = len(snis)
        deep       = self._deep_scan.get()
        cf_only    = self._cf_only_mode.get()
        gui_log("Scanner", f"اسکن {total} دامنه  |  عمیق={'بله' if deep else 'خیر'}  |  کلادفلر‌فقط={'بله' if cf_only else 'خیر'}", "INFO")
        self._set_status(f"در حال اسکن {total} دامنه…")

        done    = [0]
        cf_cnt  = [0]
        lock    = threading.Lock()

        def scan_one(sni):
            if self._stop_scan.is_set():
                return
            try:
                ip       = socket.gethostbyname(sni)
                provider = detect_provider(ip)
                ping     = tcp_ping(ip)
            except OSError:
                ip, provider, ping = "خطا", "—", 9999

            is_cf   = is_cloudflare_ip(ip) if ip != "خطا" else False
            tag     = ping_tag(ping)
            qlabel  = ping_label(ping)
            ping_s  = f"{ping} ms" if ping < 9999 else "---"

            tls_ok, alpn_str, cert_cn, cdn_sig = "", "", "", ""
            if deep and ip != "خطا" and ping < 9999:
                tls_info = tls_handshake_check(ip, sni)
                tls_ok   = "✅" if tls_info["tls"] else "❌"
                alpn_str = tls_info["alpn"] or ""
                cert_cn  = tls_info["cert_cn"] or ""
                cdn_sig  = http_probe(ip, sni)
                if cdn_sig and is_cf:
                    provider = "☁️ Cloudflare ✓"

            row = {"sni":sni,"ip":ip,"provider":provider,"ping":ping,
                   "ping_str":ping_s,"quality":qlabel,"tag":tag,
                   "is_cf":is_cf,"tls":tls_ok,"alpn":alpn_str,
                   "cert":cert_cn,"cdn_sig":cdn_sig}

            with lock:
                self._scan_results.append(row)
                done[0] += 1
                if is_cf and ping < 9999: cf_cnt[0] += 1
                d, cf = done[0], cf_cnt[0]

            if cf_only and not is_cf:
                return

            tag_use = "cf_online" if (is_cf and ping < 9999) else tag
            self.after(0, self._add_row, sni, ip, provider, ping_s, qlabel,
                       tls_ok, alpn_str, cert_cn, cdn_sig, tag_use)

            if d % 20 == 0 or d == total:
                self.after(0, self._set_status,
                           f"اسکن شد: {d} / {total}  |  ☁️ کلادفلر آنلاین: {cf}")
                self.after(0, self.lbl_count.configure, {"text": f"{d} / {total}"})

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            ex.map(scan_one, snis)

        online = sum(1 for r in self._scan_results if r["ping"] < 9999)
        cf_on  = sum(1 for r in self._scan_results if r["is_cf"] and r["ping"] < 9999)
        best   = min((r for r in self._scan_results if r["ping"] < 9999),
                     key=lambda x: x["ping"], default=None)
        stats_txt = (f"✅ آنلاین: {online}  |  ☁️ کلادفلر آنلاین: {cf_on}  |"
                     f"  🏆 بهترین: {best['sni']} ({best['ping']} ms)" if best else "")
        gui_log("Scanner", f"اسکن کامل — آنلاین:{online}  کلادفلر:{cf_on}", "SUCCESS")
        self.after(0, self._set_status,
                   f"✅ اسکن کامل — {total} دامنه  |  ☁️ کلادفلر آنلاین: {cf_on}")
        self.after(0, self.lbl_stats.configure, {"text": stats_txt})
        self.after(0, self.lbl_count.configure, {"text": f"{total} / {total}"})
        self.after(0, self.btn_scan.configure,
                   {"text":"🔍  شروع اسکن","fg_color":"#117a65","hover_color":"#0e6655"})

    def _add_row(self, sni, ip, provider, ping_str, quality,
                 tls, alpn, cert, cdn_sig, tag):
        try:
            self.tree.insert("", tk.END,
                             values=(sni, ip, provider, ping_str, quality,
                                     tls, alpn, cert, cdn_sig),
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

    def _apply_filter(self, _=None):
        q = self.e_filter.get().lower().strip()
        for k in self.tree.get_children():
            vals = [str(v).lower() for v in self.tree.item(k)["values"]]
            visible = not q or any(q in v for v in vals)
            # tkinter Treeview doesn't support hide rows natively without detach
            if not visible:
                self.tree.detach(k)
            else:
                self.tree.reattach(k, "", tk.END)

    def _show_cf_sorted(self):
        """فقط کلادفلر‌ها را بر اساس پینگ مرتب نمایش می‌دهد"""
        for i in self.tree.get_children(): self.tree.delete(i)
        cf_rows = [r for r in self._scan_results if r["is_cf"] and r["ping"] < 9999]
        cf_rows.sort(key=lambda x: x["ping"])
        for r in cf_rows:
            tag = "cf_online" if r["ping"] < 9999 else r["tag"]
            try:
                self.tree.insert("", tk.END,
                                 values=(r["sni"], r["ip"], r["provider"],
                                         r["ping_str"], r["quality"],
                                         r["tls"], r["alpn"], r["cert"], r["cdn_sig"]),
                                 tags=(tag,))
            except tk.TclError:
                pass
        self.lbl_count.configure(text=f"☁️ {len(cf_rows)} کلادفلر آنلاین")
        gui_log("Scanner", f"{len(cf_rows)} دامنه کلادفلر مرتب‌شده نمایش داده شد.", "SUCCESS")

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
            "\t".join(str(x) for x in r) for r in rows)
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
        header = "دامنه\tIP\tزیرساخت\tتأخیر\tکیفیت\tTLS\tALPN\tگواهی CN\tامضای CDN"
        lines  = [header] + [
            f"{r['sni']}\t{r['ip']}\t{r['provider']}\t{r['ping_str']}\t{r['quality']}"
            f"\t{r['tls']}\t{r['alpn']}\t{r['cert']}\t{r['cdn_sig']}"
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
            f.write("دامنه\tIP\tزیرساخت\tتأخیر\tکیفیت\tTLS\tALPN\tگواهی CN\tامضای CDN\n")
            for r in self._scan_results:
                f.write(f"{r['sni']}\t{r['ip']}\t{r['provider']}\t{r['ping_str']}\t{r['quality']}"
                        f"\t{r['tls']}\t{r['alpn']}\t{r['cert']}\t{r['cdn_sig']}\n")
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
        # نمایش تعداد
        with open(path, encoding="utf-8", errors="ignore") as f:
            cnt = sum(1 for l in f if l.strip() and not l.startswith("#"))
        gui_log("Config", f"لیست بارگذاری شد: {os.path.basename(path)}  ({cnt} دامنه)", "SUCCESS")

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
                target=lambda: self._run_asyncio_loop(cfg, local_ip),
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


    def _run_asyncio_loop(self, config, local_ip):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_srv(config, local_ip))
        finally:
            loop.close()

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
