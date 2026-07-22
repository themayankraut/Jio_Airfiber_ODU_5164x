"""
FFW Firmware Toolkit - All-in-One GUI
=======================================
Complete firmware management tool for Sercomm / Jio ODU .ffw firmware files.

  Tab 1 ─ Decrypt    AES-256-CBC chunked decryption (.ffw → .zip)
  Tab 2 ─ Edit       Modify UBIFS version parameters inside the ZIP
  Tab 3 ─ Encrypt    Re-encrypt modified ZIP back into .ffw container

Workflow:  Decrypt → Edit Parameters → Encrypt
           Each step auto-feeds its output into the next tab.

Requirements:
    pip install pycryptodome ubi_reader
    WSL with mtd-utils (for parameter repacking only):
        wsl sudo apt install -y mtd-utils python3-pip
        wsl pip3 install --break-system-packages ubi_reader

Usage:
    python ffw_toolkit.py
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Imports
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import ctypes
import hashlib
import os
import shutil
import site
import struct
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import zipfile

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad, unpad
    except ImportError:
        print("ERROR: pycryptodome is not installed.")
        print("Install it with:  pip install pycryptodome")
        sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# .ffw container format
MAGIC1 = 0x43724573
MAGIC2 = 0x216d4d6f
SIG_BLOCK_LEN  = 0x338    # 824 bytes at offset 8, hashed for AES key
IV_OFFSET      = 0x330    # 16-byte AES IV within the signed block
PAYLOAD_OFFSET = 0x440    # encrypted payload starts here
TRAILER_LEN    = 0x20     # 32-byte SHA-256 trailer at EOF — NOT ciphertext
PLAINTEXT_CHUNK = 0x10000  # 65536 = 64 KB of real data per chunk
CHUNK_SIZE      = 0x10010  # 65552 = padded ciphertext chunk (64KB + 16 PKCS7)

# UBIFS / UBI
UBIFS_NODE_MAGIC = 0x06101831
UBI_EC_MAGIC     = b"UBI#"
UBI_VID_MAGIC    = b"UBI!"
COMPR_NAMES      = {0: "none", 1: "lzo", 2: "zlib", 3: "zstd"}

# Known sysfs entry patterns (searched in order)
SYSFS_PATTERNS = [
    "firmware-update/sysfs.ubifs",   # 51641 & 51642 layout (bare UBIFS)
    "delta/image/sysfs.ubi",         # 51643 layout (UBI container)
]

# Fallback: if versions dir not found in sysfs, try oem.ubifs (51641)
OEM_PATTERNS = [
    "firmware-update/oem.ubifs",     # 51641: versions live here
]

VERSION_PARAMS = [
    ("product_name",  "Product Name"),
    ("product_class", "Product Class"),
    ("manufacturer",  "Manufacturer"),
    ("module_vendor", "Module Vendor"),
    ("hw_ver",        "HW Version"),
    ("major_ver",     "Major Version"),
    ("sw_ver",        "SW Version"),
    ("vendor_ver",    "Vendor Version"),
    ("scm_ver",       "SCM Version"),
    ("oui",           "OUI"),
    ("build_type",    "Build Type"),
    ("build_info",    "Build Info"),
]

# UI colours
CLR_BG       = "#1e1e2e"
CLR_SURFACE  = "#2a2a3d"
CLR_CARD     = "#313147"
CLR_TEXT     = "#e0e0e0"
CLR_DIM      = "#8888aa"
CLR_ACCENT   = "#7c3aed"
CLR_GREEN    = "#22c55e"
CLR_BLUE     = "#3b82f6"
CLR_ORANGE   = "#f59e0b"
CLR_RED      = "#ef4444"
CLR_INPUT_BG = "#3a3a52"
CLR_INPUT_FG = "#f0f0f0"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Core Functions — Decrypt / Encrypt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def decrypt_ffw(input_path: str, output_path: str, progress_cb=None) -> int:
    """Decrypt .ffw → ZIP. Returns output size in bytes."""
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < PAYLOAD_OFFSET:
        raise ValueError("File too small to be a valid .ffw firmware.")

    m1 = int.from_bytes(data[0:4], "little")
    m2 = int.from_bytes(data[4:8], "little")
    if m1 != MAGIC1 or m2 != MAGIC2:
        raise ValueError(
            f"Bad magic: {hex(m1)}/{hex(m2)}  "
            f"(expected {hex(MAGIC1)}/{hex(MAGIC2)})"
        )

    aes_key = hashlib.sha256(data[8 : 8 + SIG_BLOCK_LEN]).digest()
    iv      = data[IV_OFFSET : IV_OFFSET + 16]
    payload = data[PAYLOAD_OFFSET:]

    out = bytearray()
    pos, total = 0, len(payload)

    while pos < total:
        chunk = payload[pos : pos + CHUNK_SIZE]
        pos += len(chunk)
        dec = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(chunk)
        try:
            dec = unpad(dec, AES.block_size)
        except ValueError:
            pass
        out += dec
        if progress_cb:
            progress_cb(pos, total)

    with open(output_path, "wb") as f:
        f.write(out)
    return len(out)


def encrypt_ffw(template_path: str, payload_path: str,
                output_path: str, progress_cb=None) -> int:
    """Re-encrypt ZIP into .ffw using header from template. Returns output size."""
    with open(template_path, "rb") as f:
        template = f.read()

    if len(template) < PAYLOAD_OFFSET:
        raise ValueError("Template .ffw too small — not a valid header source.")

    m1 = int.from_bytes(template[0:4], "little")
    m2 = int.from_bytes(template[4:8], "little")
    if m1 != MAGIC1 or m2 != MAGIC2:
        raise ValueError(f"Template magic mismatch: {hex(m1)}/{hex(m2)}")

    header  = template[:PAYLOAD_OFFSET]
    aes_key = hashlib.sha256(header[8 : 8 + SIG_BLOCK_LEN]).digest()
    iv      = header[IV_OFFSET : IV_OFFSET + 16]

    with open(payload_path, "rb") as f:
        plaintext = f.read()

    ct = bytearray()
    pos, total = 0, len(plaintext)

    while pos < total:
        take = min(total - pos, PLAINTEXT_CHUNK)  # 64 KB per chunk
        chunk = plaintext[pos : pos + take]
        pos += take
        chunk = pad(chunk, AES.block_size)  # PKCS7 pad EVERY chunk (matches OEM)
        ct += AES.new(aes_key, AES.MODE_CBC, iv).encrypt(chunk)
        if progress_cb:
            progress_cb(pos, total)

    body = header + bytes(ct)
    output_data = body + hashlib.sha256(body).digest()

    with open(output_path, "wb") as f:
        f.write(output_data)
    return len(output_data)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Core Functions — UBIFS / UBI helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def find_ubireader_exe(name="ubireader_extract_files"):
    exe = shutil.which(name)
    if exe:
        return exe
    candidates = []
    try:
        candidates.append(
            os.path.join(os.path.dirname(site.getusersitepackages()), "Scripts"))
    except Exception:
        pass
    try:
        for sp in site.getsitepackages():
            candidates.append(os.path.join(os.path.dirname(sp), "Scripts"))
    except Exception:
        pass
    candidates.append(os.path.join(sys.prefix, "Scripts"))
    for d in candidates:
        for ext in (".exe", ""):
            p = os.path.join(d, name + ext)
            if os.path.isfile(p):
                return p
    return None


def find_sysfs_in_zip(zip_path):
    """Search a firmware ZIP for sysfs.ubifs or sysfs.ubi.
    Returns (zip_entry_name, is_ubi_container) or raises FileNotFoundError.
    """
    with zipfile.ZipFile(zip_path) as zf:
        names = [n.replace("\\", "/") for n in zf.namelist()]

    # Try known patterns first
    for pat in SYSFS_PATTERNS:
        for n in names:
            if n == pat:
                return n, n.endswith(".ubi")

    # Fallback: search for any sysfs.ubi* file
    for n in names:
        base = n.rsplit("/", 1)[-1].lower()
        if base.startswith("sysfs.") and ("ubifs" in base or "ubi" in base):
            return n, base.endswith(".ubi")

    raise FileNotFoundError(
        "No sysfs.ubifs or sysfs.ubi found in ZIP.\n"
        f"Entries: {names[:15]}…")


def read_ubifs_superblock(path):
    """Read UBIFS superblock geometry from a raw UBIFS image."""
    with open(path, "rb") as f:
        hdr = f.read(128)
    magic = struct.unpack_from("<I", hdr, 0)[0]
    if magic != UBIFS_NODE_MAGIC:
        raise ValueError(f"Invalid UBIFS magic: {hex(magic)}")
    return {
        "min_io_size": struct.unpack_from("<I", hdr, 32)[0],
        "leb_size":    struct.unpack_from("<I", hdr, 36)[0],
        "leb_cnt":     struct.unpack_from("<I", hdr, 40)[0],
        "max_leb_cnt": struct.unpack_from("<I", hdr, 44)[0],
        "compr":       COMPR_NAMES.get(struct.unpack_from("<H", hdr, 84)[0], "lzo"),
    }


def read_ubi_info(path):
    """Parse UBI container EC/VID headers + volume table.
    Returns dict with peb_size, min_io, sub_page, leb_size, volumes[].
    """
    with open(path, "rb") as f:
        ec0 = f.read(64)
        file_size = f.seek(0, 2)

    if ec0[:4] != UBI_EC_MAGIC:
        raise ValueError("Not a valid UBI image (bad EC magic).")

    vid_hdr_off = struct.unpack_from(">I", ec0, 16)[0]
    data_off    = struct.unpack_from(">I", ec0, 20)[0]

    # Determine PEB size by finding next EC header
    peb_size = None
    with open(path, "rb") as f:
        for cand in [64*1024, 128*1024, 256*1024, 512*1024, 1024*1024]:
            if cand >= file_size:
                continue
            f.seek(cand)
            if f.read(4) == UBI_EC_MAGIC:
                peb_size = cand
                break
    if not peb_size:
        raise ValueError("Cannot determine UBI PEB size.")

    # min I/O and sub-page from vid_hdr_offset
    min_io = vid_hdr_off if vid_hdr_off > 64 else 1
    sub_page = vid_hdr_off if vid_hdr_off > 1 else None
    leb_size = peb_size - data_off

    # Parse volume table from layout PEBs (first few PEBs)
    volumes = []
    with open(path, "rb") as f:
        for peb_i in range(min(4, file_size // peb_size)):
            f.seek(peb_i * peb_size + vid_hdr_off)
            vid = f.read(64)
            if vid[:4] != UBI_VID_MAGIC:
                continue
            vol_id = struct.unpack_from(">I", vid, 8)[0]
            # Internal layout volume holds the vtbl
            if vol_id >= 0x7FFFEF00:
                f.seek(peb_i * peb_size + data_off)
                for vi in range(128):
                    rec = f.read(172)
                    if len(rec) < 172:
                        break
                    rsvd = struct.unpack_from(">I", rec, 0)[0]
                    if rsvd == 0:
                        continue
                    vtype = rec[12]  # 1=dynamic 2=static
                    nlen  = struct.unpack_from(">H", rec, 14)[0]
                    vname = rec[16:16 + nlen].decode("ascii", errors="replace")
                    flags = rec[144]
                    volumes.append({
                        "vol_id": vi,
                        "vol_type": "dynamic" if vtype == 1 else "static",
                        "vol_name": vname,
                        "reserved_pebs": rsvd,
                        "autoresize": bool(flags & 1),
                    })
                break  # found vtbl, done

    return {
        "peb_size": peb_size,
        "min_io": min_io,
        "sub_page": sub_page,
        "leb_size": leb_size,
        "data_offset": data_off,
        "vid_hdr_offset": vid_hdr_off,
        "num_pebs": file_size // peb_size,
        "volumes": volumes,
    }


def extract_ubifs_from_ubi(ubi_path, output_path):
    """Extract raw UBIFS volume data from a UBI container (pure Python).
    Parses EC/VID headers, collects data LEBs for the first user volume,
    and reassembles them in logical order.  No dependency on ubireader.
    """
    with open(ubi_path, "rb") as f:
        # Read EC header for geometry
        ec0 = f.read(64)
        file_size = f.seek(0, 2)

    if ec0[:4] != UBI_EC_MAGIC:
        raise ValueError("Not a valid UBI image.")

    vid_hdr_off = struct.unpack_from(">I", ec0, 16)[0]
    data_off    = struct.unpack_from(">I", ec0, 20)[0]

    # Find PEB size
    peb_size = None
    with open(ubi_path, "rb") as f:
        for cand in [64*1024, 128*1024, 256*1024, 512*1024, 1024*1024]:
            if cand >= file_size:
                continue
            f.seek(cand)
            if f.read(4) == UBI_EC_MAGIC:
                peb_size = cand
                break
    if not peb_size:
        raise ValueError("Cannot determine UBI PEB size.")

    leb_size = peb_size - data_off
    num_pebs = file_size // peb_size

    # Scan all PEBs, collect data for non-internal volumes
    leb_map = {}  # lnum → data bytes
    target_vol_id = None

    with open(ubi_path, "rb") as f:
        for peb_i in range(num_pebs):
            peb_start = peb_i * peb_size

            # Check EC header
            f.seek(peb_start)
            if f.read(4) != UBI_EC_MAGIC:
                continue

            # Read VID header
            f.seek(peb_start + vid_hdr_off)
            vid = f.read(64)
            if vid[:4] != UBI_VID_MAGIC:
                continue

            vol_id = struct.unpack_from(">I", vid, 8)[0]

            # Skip internal UBI volumes (layout, fastmap, etc.)
            if vol_id >= 0x7FFFEF00:
                continue

            # Lock onto the first user volume we find
            if target_vol_id is None:
                target_vol_id = vol_id
            if vol_id != target_vol_id:
                continue

            lnum = struct.unpack_from(">I", vid, 12)[0]

            # Read the data portion of this PEB
            f.seek(peb_start + data_off)
            leb_data = f.read(leb_size)

            # Keep the latest copy (highest sqnum) if duplicate lnum
            # sqnum is 8 bytes big-endian at VID header offset 40
            sqnum = struct.unpack_from(">Q", vid, 40)[0]
            if lnum not in leb_map or sqnum > leb_map[lnum][0]:
                leb_map[lnum] = (sqnum, leb_data)

    if not leb_map:
        raise ValueError("No user volume data found in UBI image.")

    # Reassemble LEBs in logical order
    with open(output_path, "wb") as out:
        for lnum in sorted(leb_map.keys()):
            out.write(leb_map[lnum][1])


def win_to_wsl(path):
    drive, rest = os.path.splitdrive(os.path.abspath(path))
    return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")


def long_path(path):
    try:
        buf = ctypes.create_unicode_buffer(1024)
        if ctypes.windll.kernel32.GetLongPathNameW(path, buf, 1024):
            return buf.value
    except Exception:
        pass
    return path


def wsl_ok():
    try:
        r = subprocess.run(["wsl", "bash", "-c", "echo ok"],
                           capture_output=True, text=True, timeout=30)
        return "ok" in r.stdout
    except Exception:
        return False


def wsl_has(cmd):
    try:
        r = subprocess.run(["wsl", "which", cmd],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def zip_tail_bytes(path):
    with open(path, "rb") as f:
        raw = f.read()
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0:
        return b""
    comment_len = struct.unpack_from("<H", raw, eocd + 20)[0]
    return raw[eocd + 22 + comment_len :]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Styled widgets
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def make_entry(parent, textvariable=None, **kw):
    """Dark-themed entry widget."""
    e = tk.Entry(parent, textvariable=textvariable,
                 bg=CLR_INPUT_BG, fg=CLR_INPUT_FG, insertbackground=CLR_INPUT_FG,
                 relief="flat", font=("Consolas", 10), highlightthickness=1,
                 highlightbackground="#555", highlightcolor=CLR_ACCENT, **kw)
    return e


def make_button(parent, text, command, colour, **kw):
    """Coloured action button."""
    return tk.Button(parent, text=text, command=command,
                     bg=colour, fg="white", activebackground=colour,
                     activeforeground="white", font=("Segoe UI", 10, "bold"),
                     relief="flat", cursor="hand2", bd=0, **kw)


def make_label(parent, text, **kw):
    return tk.Label(parent, text=text, bg=CLR_SURFACE, fg=CLR_TEXT,
                    font=("Segoe UI", 9), **kw)


def make_heading(parent, text):
    return tk.Label(parent, text=text, bg=CLR_SURFACE, fg=CLR_TEXT,
                    font=("Segoe UI", 10, "bold"), anchor="w")


def make_browse_row(parent, label_text, var, browse_cmd, row):
    """Create a label + entry + browse button row on a grid."""
    make_label(parent, text=label_text, anchor="w").grid(
        row=row, column=0, sticky="w", padx=12, pady=(8, 2), columnspan=3)
    e = make_entry(parent, textvariable=var)
    e.grid(row=row + 1, column=0, columnspan=2, sticky="we", padx=12, pady=(0, 4))
    make_button(parent, "Browse…", browse_cmd, "#555", width=8).grid(
        row=row + 1, column=2, padx=(4, 12), pady=(0, 4))
    return e


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Application
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class FFWToolkit:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("FFW Firmware Toolkit")
        root.geometry("820x820")
        root.minsize(750, 700)
        root.configure(bg=CLR_BG)

        # Shared state for passing data between tabs
        self.last_ffw_path = None       # original .ffw (template for encrypt)
        self.last_decrypted_zip = None  # decrypted ZIP path
        self.last_modified_zip = None   # modified ZIP path (after param edit)

        # UBIFS editor state
        self.work_dir = None
        self.ubifs_path = None
        self.ubifs_info = {}
        self.is_ubi = False          # True if ZIP contains .ubi (not bare .ubifs)
        self.ubi_info = {}           # UBI container geometry (only when is_ubi)
        self.ubi_path = None         # path to extracted .ubi file
        self.sysfs_zip_entry = None  # ZIP entry name for sysfs
        self.versions_dir = None
        self.original_params = {}
        self.param_widgets = {}

        self._build_ui()

    # ──────────────────────────────────────────────────────────────────────
    #  UI construction
    # ──────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg="#12122a", height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔧  FFW Firmware Toolkit",
                 font=("Segoe UI", 15, "bold"),
                 bg="#12122a", fg="white", padx=16).pack(side="left", fill="y")
        tk.Label(hdr, text="Decrypt  ▸  Edit  ▸  Encrypt",
                 font=("Segoe UI", 10), bg="#12122a", fg=CLR_DIM,
                 padx=16).pack(side="right", fill="y")

        # ── Notebook ─────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook", background=CLR_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                         background=CLR_CARD, foreground=CLR_DIM,
                         padding=[20, 10], font=("Segoe UI", 10, "bold"))
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", CLR_ACCENT)],
                  foreground=[("selected", "white")])

        self.notebook = ttk.Notebook(self.root, style="Dark.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        # Tab 1 — Decrypt
        tab1 = tk.Frame(self.notebook, bg=CLR_SURFACE)
        self.notebook.add(tab1, text="  1 ─ Decrypt  ")
        self._build_decrypt_tab(tab1)

        # Tab 2 — Edit Parameters
        tab2 = tk.Frame(self.notebook, bg=CLR_SURFACE)
        self.notebook.add(tab2, text="  2 ─ Edit Parameters  ")
        self._build_editor_tab(tab2)

        # Tab 3 — Encrypt
        tab3 = tk.Frame(self.notebook, bg=CLR_SURFACE)
        self.notebook.add(tab3, text="  3 ─ Encrypt  ")
        self._build_encrypt_tab(tab3)

        # ── Bottom bar (shared progress + status) ────────────────────
        bot = tk.Frame(self.root, bg="#12122a", height=60)
        bot.pack(fill="x", side="bottom")
        bot.pack_propagate(False)

        self.progress = ttk.Progressbar(bot, mode="determinate", length=780)
        self.progress.pack(padx=16, pady=(10, 2))

        self.status_var = tk.StringVar(value="Ready — start by decrypting a .ffw file.")
        tk.Label(bot, textvariable=self.status_var, bg="#12122a", fg=CLR_DIM,
                 font=("Segoe UI", 8), anchor="w", padx=16).pack(
                     fill="x", pady=(0, 6))

    # ──────────────────────────────────────────────────────────────────────
    #  Tab 1 — Decrypt
    # ──────────────────────────────────────────────────────────────────────

    def _build_decrypt_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        tk.Label(parent, text="Decrypt a .ffw firmware file into a ZIP archive.",
                 bg=CLR_SURFACE, fg=CLR_DIM, font=("Segoe UI", 9),
                 anchor="w").grid(row=0, column=0, columnspan=3,
                                  sticky="we", padx=12, pady=(14, 4))

        self.dec_input_var = tk.StringVar()
        make_browse_row(parent, "Input .ffw file:", self.dec_input_var,
                        self._dec_browse_input, 1)

        self.dec_output_var = tk.StringVar()
        make_browse_row(parent, "Output folder:", self.dec_output_var,
                        self._dec_browse_output, 3)

        self.dec_btn = make_button(parent, "🔓  Decrypt Firmware",
                                   self._dec_start, CLR_GREEN, height=2)
        self.dec_btn.grid(row=5, column=0, columnspan=3, sticky="we",
                          padx=12, pady=(20, 12))

        # Next step hint
        self.dec_next_var = tk.StringVar()
        tk.Label(parent, textvariable=self.dec_next_var, bg=CLR_SURFACE,
                 fg=CLR_GREEN, font=("Segoe UI", 9), anchor="w",
                 cursor="hand2").grid(row=6, column=0, columnspan=3,
                                      sticky="we", padx=12)

    def _dec_browse_input(self):
        p = filedialog.askopenfilename(
            title="Select .ffw firmware file",
            filetypes=[("Firmware", "*.ffw"), ("All", "*.*")])
        if p:
            self.dec_input_var.set(p)
            if not self.dec_output_var.get():
                self.dec_output_var.set(os.path.dirname(p))

    def _dec_browse_output(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.dec_output_var.set(p)

    def _dec_start(self):
        inp = self.dec_input_var.get().strip()
        out_dir = self.dec_output_var.get().strip()
        if not inp or not os.path.isfile(inp):
            messagebox.showerror("Error", "Select a valid .ffw file.")
            return
        if not out_dir or not os.path.isdir(out_dir):
            messagebox.showerror("Error", "Select a valid output folder.")
            return

        base = os.path.splitext(os.path.basename(inp))[0]
        out_path = os.path.join(out_dir, base + ".decrypted.zip")

        self.dec_btn.config(state="disabled")
        self.progress["value"] = 0
        self._status("Decrypting…")
        threading.Thread(target=self._dec_run, args=(inp, out_path),
                         daemon=True).start()

    def _dec_run(self, inp, out):
        def cb(done, total):
            pct = int(done / total * 100) if total else 0
            self.root.after(0, lambda v=pct: self.progress.config(value=v))
        try:
            size = decrypt_ffw(inp, out, progress_cb=cb)
            self.last_ffw_path = inp
            self.last_decrypted_zip = out
            self.root.after(0, lambda: self._dec_done(out, size))
        except Exception as exc:
            msg = str(exc)
            self.root.after(0, lambda m=msg: self._dec_fail(m))

    def _dec_done(self, path, size):
        self.progress["value"] = 100
        self.dec_btn.config(state="normal")
        self._status(f"Decrypted → {os.path.basename(path)}  ({size:,} bytes)")

        # Auto-fill editor tab
        self.edit_zip_var.set(path)

        # Auto-fill encrypt tab template
        if self.last_ffw_path:
            self.enc_template_var.set(self.last_ffw_path)

        self.dec_next_var.set("✓  Done! Switch to tab 2 to edit parameters →")
        messagebox.showinfo("Decrypt Complete",
            f"Saved to:\n{path}\n\n{size:,} bytes\n\n"
            "Switch to the 'Edit Parameters' tab to modify firmware settings.")

    def _dec_fail(self, msg):
        self.dec_btn.config(state="normal")
        self._status("Decryption failed.")
        messagebox.showerror("Decrypt Failed", msg)

    # ──────────────────────────────────────────────────────────────────────
    #  Tab 2 — Edit Parameters
    # ──────────────────────────────────────────────────────────────────────

    def _build_editor_tab(self, parent):
        parent.columnconfigure(0, weight=1)

        # ZIP selection row
        top = tk.Frame(parent, bg=CLR_SURFACE)
        top.pack(fill="x", padx=12, pady=(12, 4))
        make_label(top, text="Decrypted ZIP:").pack(side="left")
        self.edit_zip_var = tk.StringVar()
        make_entry(top, textvariable=self.edit_zip_var).pack(
            side="left", fill="x", expand=True, padx=(8, 4))
        make_button(top, "Browse…", self._edit_browse, "#555", width=8).pack(side="left")
        make_button(top, "⬇ Load", self._edit_load, CLR_BLUE, width=8).pack(
            side="left", padx=(8, 0))

        # UBIFS info
        self.edit_info_var = tk.StringVar(value="Load a decrypted ZIP to view parameters.")
        tk.Label(parent, textvariable=self.edit_info_var, bg=CLR_SURFACE,
                 fg=CLR_DIM, font=("Consolas", 8), anchor="w").pack(
                     fill="x", padx=12, pady=(2, 4))

        # Scrollable parameter area
        param_frame = tk.Frame(parent, bg=CLR_SURFACE)
        param_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        canvas = tk.Canvas(param_frame, bg=CLR_CARD, highlightthickness=0,
                           borderwidth=0)
        vscroll = tk.Scrollbar(param_frame, orient="vertical",
                               command=canvas.yview, bg=CLR_CARD,
                               troughcolor=CLR_SURFACE)
        self.edit_inner = tk.Frame(canvas, bg=CLR_CARD)
        self.edit_inner.bind("<Configure>",
            lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.edit_inner, anchor="nw",
                             tags="inner")
        canvas.configure(yscrollcommand=vscroll.set)
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig("inner", width=e.width))
        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        def _mw(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _mw)

        # Build parameter rows
        for i, (key, label) in enumerate(VERSION_PARAMS):
            row_bg = CLR_CARD if i % 2 == 0 else CLR_SURFACE
            row = tk.Frame(self.edit_inner, bg=row_bg, padx=10, pady=6)
            row.pack(fill="x")
            row.columnconfigure(1, weight=1)

            tk.Label(row, text=label + ":", font=("Segoe UI", 9, "bold"),
                     bg=row_bg, fg=CLR_TEXT, width=16, anchor="e").grid(
                         row=0, column=0, sticky="ne", padx=(0, 10))

            if key == "build_info":
                txt = tk.Text(row, height=4, font=("Consolas", 10),
                              bg=CLR_INPUT_BG, fg=CLR_INPUT_FG,
                              insertbackground=CLR_INPUT_FG,
                              relief="flat", wrap="none",
                              highlightthickness=1,
                              highlightbackground="#555",
                              highlightcolor=CLR_ACCENT)
                txt.grid(row=0, column=1, sticky="we")
                self.param_widgets[key] = txt
            else:
                var = tk.StringVar()
                ent = make_entry(row, textvariable=var)
                ent.grid(row=0, column=1, sticky="we")
                self.param_widgets[key] = (ent, var)

        # Repack button
        self.edit_repack_btn = make_button(
            parent, "💾  Save & Repack Modified ZIP",
            self._edit_repack, CLR_BLUE, height=2, state="disabled")
        self.edit_repack_btn.pack(fill="x", padx=12, pady=(4, 12))

    def _edit_browse(self):
        p = filedialog.askopenfilename(
            title="Select decrypted ZIP",
            filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
        if p:
            self.edit_zip_var.set(p)

    def _edit_load(self):
        path = self.edit_zip_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Select a valid ZIP file.")
            return
        self._set_busy(True)
        self._status("Extracting UBIFS…")
        threading.Thread(target=self._edit_do_load, args=(path,),
                         daemon=True).start()

    def _edit_do_load(self, zip_path):
        try:
            if self.work_dir and os.path.isdir(self.work_dir):
                shutil.rmtree(self.work_dir, ignore_errors=True)
            self.work_dir = long_path(tempfile.mkdtemp(prefix="fw_edit_"))

            # 1) Find sysfs entry in ZIP (auto-detect layout)
            self._status("Scanning ZIP layout…")
            entry_name, is_ubi = find_sysfs_in_zip(zip_path)
            self.sysfs_zip_entry = entry_name
            self.is_ubi = is_ubi
            fmt_label = "UBI container" if is_ubi else "bare UBIFS"
            self._status(f"Found {entry_name} ({fmt_label})")

            # 2) Extract from ZIP
            self._status("Extracting from ZIP…")
            with zipfile.ZipFile(zip_path) as zf:
                # namelist may use backslashes on Windows
                actual = None
                for n in zf.namelist():
                    if n.replace("\\", "/") == entry_name:
                        actual = n
                        break
                if not actual:
                    raise FileNotFoundError(f"'{entry_name}' not in ZIP.")
                zf.extract(actual, self.work_dir)

            extracted = os.path.join(
                self.work_dir, actual.replace("/", os.sep))

            # 3) If UBI, extract the UBIFS volume from the UBI container
            if is_ubi:
                self._status("Parsing UBI container…")
                self.ubi_path = extracted
                self.ubi_info = read_ubi_info(extracted)

                self._status("Extracting UBIFS from UBI container…")
                ubifs_out = os.path.join(self.work_dir, "sysfs_extracted.ubifs")
                extract_ubifs_from_ubi(extracted, ubifs_out)

                if not os.path.isfile(ubifs_out) or os.path.getsize(ubifs_out) < 1024:
                    raise RuntimeError(
                        "UBIFS extraction from UBI container produced "
                        "empty or missing output.")
                extracted = ubifs_out

            self.ubifs_path = extracted

            # 4) Read superblock
            self._status("Reading UBIFS superblock…")
            self.ubifs_info = read_ubifs_superblock(self.ubifs_path)

            # 5) Extract filesystem (try Windows ubireader, fallback to WSL)
            self._status("Extracting UBIFS filesystem…")
            extract_out = os.path.join(self.work_dir, "rootfs")
            win_ok = False

            # Try Windows ubireader first
            exe = find_ubireader_exe()
            if exe:
                env = os.environ.copy()
                env["PYTHONUTF8"] = "1"
                env["PYTHONIOENCODING"] = "utf-8"
                proc = subprocess.run(
                    [exe, self.ubifs_path, "-o", extract_out],
                    capture_output=True, env=env)
                win_ok = os.path.isdir(extract_out)

            # Fallback to WSL ubireader if Windows failed
            if not win_ok:
                self._status("Windows ubireader failed, trying WSL…")
                if not wsl_ok():
                    raise RuntimeError(
                        "UBIFS extraction failed on Windows and WSL "
                        "is not available.\nInstall WSL: wsl --install")

                wsl_ubifs = win_to_wsl(self.ubifs_path)
                wsl_rootfs = win_to_wsl(
                    os.path.join(self.work_dir, "rootfs"))
                extract_script = f"""#!/bin/bash
set -e
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
rm -rf "{wsl_rootfs}"

if command -v ubireader_extract_files &>/dev/null; then
    ubireader_extract_files "{wsl_ubifs}" -o "{wsl_rootfs}"
elif [ -f "$HOME/.local/bin/ubireader_extract_files" ]; then
    "$HOME/.local/bin/ubireader_extract_files" "{wsl_ubifs}" -o "{wsl_rootfs}"
else
    echo "ERROR: ubireader not in WSL" >&2; exit 1
fi
echo "EXTRACT_OK"
"""
                script_path = os.path.join(
                    self.work_dir, "extract.sh")
                with open(script_path, "w", encoding="utf-8",
                          newline="\n") as f:
                    f.write(extract_script)

                proc = subprocess.run(
                    ["wsl", "bash", win_to_wsl(script_path)],
                    capture_output=True, text=True, timeout=300)

                if "EXTRACT_OK" not in proc.stdout:
                    detail = (proc.stdout + "\n" + proc.stderr).strip()
                    raise RuntimeError(
                        f"WSL UBIFS extraction failed:\n"
                        f"{detail[:600]}")

            if not os.path.isdir(extract_out):
                raise RuntimeError(
                    "UBIFS filesystem extraction produced no output.")

            # 6) Find versions directory — first in sysfs, then in oem.ubifs (51641)
            self._status("Reading parameters…")
            versions_dir = None

            def _find_versions_in(rootfs_path):
                """Return versions dir path if found, else None."""
                for dp, dn, fn in os.walk(rootfs_path):
                    try:
                        if os.path.basename(dp) == "versions" and "sw_ver" in fn:
                            return dp
                    except OSError:
                        continue
                # Also try hardcoded candidate
                for candidate in [
                    os.path.join(rootfs_path, "usr", "etc", "versions"),
                ]:
                    if os.path.isdir(candidate) and os.path.isfile(
                            os.path.join(candidate, "sw_ver")):
                        return candidate
                return None

            versions_dir = _find_versions_in(extract_out)

            # Fallback: try oem.ubifs (51641 stores versions there)
            if not versions_dir:
                self._status("Versions not in sysfs — trying oem.ubifs…")
                with zipfile.ZipFile(zip_path) as zf:
                    zip_names = [n.replace("\\", "/") for n in zf.namelist()]
                    oem_entry = None
                    for pat in OEM_PATTERNS:
                        if pat in zip_names:
                            oem_entry = pat
                            break

                if oem_entry:
                    self._status(f"Extracting {oem_entry}…")
                    with zipfile.ZipFile(zip_path) as zf:
                        for n in zf.namelist():
                            if n.replace("\\", "/") == oem_entry:
                                zf.extract(n, self.work_dir)
                                oem_extracted = os.path.join(
                                    self.work_dir, n.replace("/", os.sep))
                                break

                    oem_rootfs = os.path.join(self.work_dir, "oem_rootfs")
                    win_ok2 = False
                    exe2 = find_ubireader_exe()
                    if exe2:
                        env2 = os.environ.copy()
                        env2["PYTHONUTF8"] = "1"
                        env2["PYTHONIOENCODING"] = "utf-8"
                        proc2 = subprocess.run(
                            [exe2, oem_extracted, "-o", oem_rootfs],
                            capture_output=True, env=env2, timeout=300)
                        win_ok2 = os.path.isdir(oem_rootfs)

                    if not win_ok2 and wsl_ok():
                        wsl_oem = win_to_wsl(oem_extracted)
                        wsl_oem_rootfs = win_to_wsl(oem_rootfs)
                        oem_script = f"""#!/bin/bash
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
ubireader_extract_files "{wsl_oem}" -o "{wsl_oem_rootfs}" 2>/dev/null
echo "OEM_OK"
"""
                        oem_script_path = os.path.join(
                            self.work_dir, "extract_oem.sh")
                        with open(oem_script_path, "w",
                                  encoding="utf-8", newline="\n") as f:
                            f.write(oem_script)
                        proc2 = subprocess.run(
                            ["wsl", "bash", win_to_wsl(oem_script_path)],
                            capture_output=True, text=True, timeout=300)
                        win_ok2 = os.path.isdir(oem_rootfs)

                    if os.path.isdir(oem_rootfs):
                        versions_dir = _find_versions_in(oem_rootfs)
                        if versions_dir:
                            # Use oem.ubifs geometry for repack
                            self.ubifs_info = read_ubifs_superblock(
                                oem_extracted)
                            self.ubifs_path = oem_extracted
                            self.sysfs_zip_entry = oem_entry
                            self.is_ubi = False

            if not versions_dir:
                raise FileNotFoundError(
                    "Could not find usr/etc/versions in extracted FS.\n"
                    "Checked: sysfs.ubifs and oem.ubifs")
            self.versions_dir = versions_dir


            # 7) Read parameters
            params = {}
            for key, _ in VERSION_PARAMS:
                fp = os.path.join(versions_dir, key)
                if os.path.isfile(fp):
                    with open(fp, "r", encoding="utf-8",
                              errors="replace") as fh:
                        params[key] = fh.read().rstrip("\n")
                else:
                    params[key] = ""
            self.original_params = dict(params)

            self.root.after(0, lambda p=params: self._edit_populate(p))
            self.root.after(0, lambda: self._set_busy(False))
            self.root.after(0, lambda: self._status(
                "Parameters loaded — edit values and repack."))
        except Exception as exc:
            msg = str(exc)
            self.root.after(0, lambda: self._set_busy(False))
            self.root.after(0, lambda m=msg: self._status(f"Error: {m}"))
            self.root.after(0, lambda m=msg: messagebox.showerror(
                "Load Failed", m))

    def _edit_populate(self, params):
        for key, val in params.items():
            w = self.param_widgets.get(key)
            if w is None:
                continue
            if isinstance(w, tk.Text):
                w.delete("1.0", "end")
                w.insert("1.0", val)
            else:
                _, var = w
                var.set(val)
        info = self.ubifs_info
        info_text = (
            f"UBIFS  ▸  min_io={info['min_io_size']}  "
            f"leb={info['leb_size']}  cnt={info['leb_cnt']}  "
            f"max={info['max_leb_cnt']}  compr={info['compr']}")
        if self.is_ubi and self.ubi_info:
            ui = self.ubi_info
            vols = ", ".join(v["vol_name"] for v in ui.get("volumes", []))
            info_text += (
                f"   |   UBI  ▸  PEB={ui['peb_size']//1024}K  "
                f"LEB={ui['leb_size']}  PEBs={ui['num_pebs']}  "
                f"vols=[{vols}]")
        self.edit_info_var.set(info_text)
        self.edit_repack_btn.config(state="normal")

    def _collect_params(self):
        params = {}
        for key, _ in VERSION_PARAMS:
            w = self.param_widgets.get(key)
            if isinstance(w, tk.Text):
                params[key] = w.get("1.0", "end").rstrip("\n")
            else:
                _, var = w
                params[key] = var.get().strip()
        return params

    def _edit_repack(self):
        if not self.ubifs_path:
            messagebox.showerror("Error", "Load parameters first.")
            return
        if not wsl_ok():
            messagebox.showerror("WSL Required",
                "WSL is needed for UBIFS repacking.\n\n"
                "Install:  wsl --install\n"
                "Then:  wsl sudo apt install -y mtd-utils python3-pip\n"
                "       wsl pip3 install --break-system-packages ubi_reader")
            return
        if not wsl_has("mkfs.ubifs"):
            messagebox.showerror("mkfs.ubifs Required",
                "Install in WSL:\n  wsl sudo apt install -y mtd-utils")
            return

        base = os.path.splitext(os.path.basename(
            self.edit_zip_var.get()))[0]
        out = filedialog.asksaveasfilename(
            title="Save modified ZIP as…",
            initialfile=base + ".modified.zip",
            defaultextension=".zip",
            filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
        if not out:
            return

        self._set_busy(True)
        self._status("Repacking UBIFS…")
        threading.Thread(target=self._edit_do_repack, args=(out,),
                         daemon=True).start()

    def _edit_do_repack(self, out_path):
        try:
            params = self._collect_params()
            changed = [k for k in params
                       if params[k] != self.original_params.get(k, "")]
            if not changed:
                self.root.after(0, lambda: messagebox.showinfo(
                    "No Changes", "No parameters were modified."))
                self.root.after(0, lambda: self._set_busy(False))
                return

            # Write modified versions
            mod_dir = os.path.join(self.work_dir, "mod_versions")
            os.makedirs(mod_dir, exist_ok=True)
            for k, v in params.items():
                with open(os.path.join(mod_dir, k), "w",
                          encoding="utf-8", newline="\n") as f:
                    f.write(v + "\n")

            info = self.ubifs_info
            wsl_work = win_to_wsl(self.work_dir)
            wsl_ubifs = win_to_wsl(self.ubifs_path)
            wsl_mod = win_to_wsl(mod_dir)
            wsl_out_ubifs = wsl_work + "/sysfs_new.ubifs"
            wsl_rootfs = wsl_work + "/wsl_rootfs"

            # Build the WSL script — handle both .ubifs and .ubi
            if self.is_ubi:
                # For UBI: mkfs.ubifs → ubinize
                ui = self.ubi_info
                wsl_out_ubi = wsl_work + "/sysfs_new.ubi"
                wsl_cfg = wsl_work + "/ubinize.cfg"

                # Build ubinize config from parsed volume table
                vol = ui["volumes"][0] if ui["volumes"] else {
                    "vol_id": 0, "vol_type": "dynamic",
                    "vol_name": "sysfs", "autoresize": True
                }
                cfg_lines = [
                    f"[{vol['vol_name']}]",
                    "mode=ubi",
                    f"image={wsl_work}/sysfs_new.ubifs",
                    f"vol_id={vol['vol_id']}",
                    f"vol_type={vol['vol_type']}",
                    f"vol_name={vol['vol_name']}",
                ]
                if vol.get("autoresize"):
                    cfg_lines.append("vol_flags=autoresize")
                else:
                    cfg_lines.append(
                        f"vol_size={vol.get('reserved_pebs', 0) * ui['leb_size']}")

                cfg_path = os.path.join(self.work_dir, "ubinize.cfg")
                with open(cfg_path, "w", encoding="utf-8",
                          newline="\n") as f:
                    f.write("\n".join(cfg_lines) + "\n")

                sub_page_flag = ""
                if ui.get("sub_page") and ui["sub_page"] > 1:
                    sub_page_flag = f"-s {ui['sub_page']}"

                total_steps = 5
                script = f"""#!/bin/bash
set -e
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

echo "[1/{total_steps}] Checking ubi_reader…"
if command -v ubireader_extract_files &>/dev/null; then
    UBIREADER_CMD="ubireader_extract_files"
elif [ -f "$HOME/.local/bin/ubireader_extract_files" ]; then
    UBIREADER_CMD="$HOME/.local/bin/ubireader_extract_files"
elif python3 -c "import ubireader" 2>/dev/null; then
    UBIREADER_CMD="python3 -m ubireader.ubifs.extract"
else
    echo "ERROR: ubi_reader not found in WSL" >&2
    exit 1
fi
echo "  Using: $UBIREADER_CMD"

echo "[2/{total_steps}] Extracting UBIFS…"
rm -rf "{wsl_rootfs}"
$UBIREADER_CMD "{wsl_ubifs}" -o "{wsl_rootfs}"

VERSIONS_DIR=$(find "{wsl_rootfs}" -path "*/usr/etc/versions" -type d | head -1)
if [ -z "$VERSIONS_DIR" ]; then
    echo "ERROR: versions dir not found" >&2; exit 1
fi
FS_ROOT=$(echo "$VERSIONS_DIR" | sed 's|/usr/etc/versions||')

echo "[3/{total_steps}] Applying changes…"
cp -f "{wsl_mod}"/* "$VERSIONS_DIR/"

echo "[4/{total_steps}] Repacking UBIFS…"
mkfs.ubifs -r "$FS_ROOT" \\
    -m {info['min_io_size']} -e {info['leb_size']} \\
    -c {info['max_leb_cnt']} -x {info['compr']} \\
    -o "{wsl_out_ubifs}"

echo "[5/{total_steps}] Wrapping in UBI container…"
ubinize -o "{wsl_out_ubi}" \\
    -m {ui['min_io']} -p {ui['peb_size']} {sub_page_flag} \\
    "{wsl_cfg}"

echo "REPACK_SUCCESS"
"""
                replace_file = os.path.join(
                    self.work_dir, "sysfs_new.ubi")
            else:
                # Bare UBIFS — just mkfs.ubifs
                total_steps = 4
                script = f"""#!/bin/bash
set -e
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

echo "[1/{total_steps}] Checking ubi_reader…"
if command -v ubireader_extract_files &>/dev/null; then
    UBIREADER_CMD="ubireader_extract_files"
elif [ -f "$HOME/.local/bin/ubireader_extract_files" ]; then
    UBIREADER_CMD="$HOME/.local/bin/ubireader_extract_files"
elif python3 -c "import ubireader" 2>/dev/null; then
    UBIREADER_CMD="python3 -m ubireader.ubifs.extract"
else
    echo "ERROR: ubi_reader not found in WSL" >&2
    exit 1
fi
echo "  Using: $UBIREADER_CMD"

echo "[2/{total_steps}] Extracting UBIFS…"
rm -rf "{wsl_rootfs}"
$UBIREADER_CMD "{wsl_ubifs}" -o "{wsl_rootfs}"

VERSIONS_DIR=$(find "{wsl_rootfs}" -path "*/usr/etc/versions" -type d | head -1)
if [ -z "$VERSIONS_DIR" ]; then
    echo "ERROR: versions dir not found" >&2; exit 1
fi
FS_ROOT=$(echo "$VERSIONS_DIR" | sed 's|/usr/etc/versions||')

echo "[3/{total_steps}] Applying changes…"
cp -f "{wsl_mod}"/* "$VERSIONS_DIR/"

echo "[4/{total_steps}] Repacking UBIFS…"
mkfs.ubifs -r "$FS_ROOT" \\
    -m {info['min_io_size']} -e {info['leb_size']} \\
    -c {info['max_leb_cnt']} -x {info['compr']} \\
    -o "{wsl_out_ubifs}"

echo "REPACK_SUCCESS"
"""
                replace_file = os.path.join(
                    self.work_dir, "sysfs_new.ubifs")

            script_path = os.path.join(self.work_dir, "repack.sh")
            with open(script_path, "w", encoding="utf-8",
                      newline="\n") as f:
                f.write(script)

            self._status("Running repack in WSL…")
            result = subprocess.run(
                ["wsl", "bash", win_to_wsl(script_path)],
                capture_output=True, text=True, timeout=600)

            if "REPACK_SUCCESS" not in result.stdout:
                detail = (result.stdout + "\n" + result.stderr).strip()
                raise RuntimeError(f"WSL repack failed:\n{detail[:800]}")

            if not os.path.isfile(replace_file):
                raise FileNotFoundError(
                    f"Repacked image not created: {replace_file}")

            # Rebuild ZIP — replace the sysfs entry with the new image
            self._status("Rebuilding ZIP…")
            zip_path = self.edit_zip_var.get().strip()
            tail = zip_tail_bytes(zip_path)
            temp = out_path + ".tmp"
            sysfs_entry = self.sysfs_zip_entry  # dynamic, not hardcoded

            with zipfile.ZipFile(zip_path, "r") as zin, \
                 zipfile.ZipFile(temp, "w") as zout:
                for item in zin.infolist():
                    if item.filename.replace("\\", "/") == sysfs_entry:
                        ni = zipfile.ZipInfo(sysfs_entry,
                                             date_time=item.date_time)
                        ni.compress_type = item.compress_type
                        with open(replace_file, "rb") as nf:
                            zout.writestr(ni, nf.read())
                    else:
                        zout.writestr(item, zin.read(item.filename))
            if tail:
                with open(temp, "ab") as f:
                    f.write(tail)
            if os.path.exists(out_path):
                os.remove(out_path)
            shutil.move(temp, out_path)

            self.last_modified_zip = out_path
            n_changed = len(changed)

            # --- NEW: Update MD5 hash in updater script ---
            self._status("Updating MD5 in updater script…")
            try:
                import hashlib
                
                # Get name and size of newly packed image
                sys_basename = os.path.basename(sysfs_entry)
                new_size = os.path.getsize(replace_file)
                
                # Calc new MD5
                h = hashlib.md5()
                with open(replace_file, 'rb') as f:
                    for chunk in iter(lambda: f.read(1048576), b''):
                        h.update(chunk)
                new_md5 = h.hexdigest()
                
                temp2 = out_path + ".tmp2"
                script_updated = False
                
                with zipfile.ZipFile(out_path, "r") as zin, \
                     zipfile.ZipFile(temp2, "w") as zout:
                    for item in zin.infolist():
                        if "updater_script" in item.filename:
                            script_content = zin.read(item.filename).decode('utf-8', errors='replace')
                            lines = script_content.splitlines()
                            new_lines = []
                            for line in lines:
                                parts = line.split(',')
                                # e.g. addfile,system,68943872,9b119acd...
                                if len(parts) >= 4 and parts[0] == 'addfile' and (parts[1] == 'system' or sys_basename in parts[1]):
                                    new_line = f"addfile,{parts[1]},{new_size},{new_md5}"
                                    new_lines.append(new_line)
                                    script_updated = True
                                else:
                                    new_lines.append(line)
                            
                            zout.writestr(item, "\n".join(new_lines) + "\n")
                        else:
                            zout.writestr(item, zin.read(item.filename))
                
                if script_updated:
                    if tail:
                        with open(temp2, "ab") as f:
                            f.write(tail)
                    os.remove(out_path)
                    shutil.move(temp2, out_path)
                    self._status("MD5 updated in updater script!")
                else:
                    if os.path.exists(temp2):
                        os.remove(temp2)
                    self._status("No updater script found to update (ignoring).")
            except Exception as e:
                print("Failed to update MD5 hash:", e)
                # Soft fail, don't crash the repack
            # ----------------------------------------------
            
            # Auto-fill encrypt tab

            self.root.after(0, lambda: self.enc_payload_var.set(out_path))

            self.root.after(0, lambda: self._set_busy(False))
            self.root.after(0, lambda: self._status(
                f"Repacked! {n_changed} param(s) changed → "
                f"{os.path.basename(out_path)}"))
            self.root.after(0, lambda: messagebox.showinfo(
                "Repack Complete",
                f"Modified ZIP saved to:\n{out_path}\n\n"
                f"Changed: {', '.join(changed)}\n\n"
                "Switch to tab 3 to encrypt back into .ffw format."))

        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: self._set_busy(False))
            self.root.after(0, lambda: messagebox.showerror(
                "Timeout", "WSL repack timed out (10 min)."))
        except Exception as exc:
            msg = str(exc)
            self.root.after(0, lambda: self._set_busy(False))
            self.root.after(0, lambda m=msg: self._status(f"Error: {m}"))
            self.root.after(0, lambda m=msg: messagebox.showerror(
                "Repack Failed", m))

    # ──────────────────────────────────────────────────────────────────────
    #  Tab 3 — Encrypt
    # ──────────────────────────────────────────────────────────────────────

    def _build_encrypt_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        # Warning
        tk.Label(parent,
            text="⚠  Re-encrypts using the original .ffw header & signature.\n"
                 "    The RSA signature only covers the header, not the payload.\n"
                 "    Use only on hardware you own. Keep a recovery method ready.",
            bg=CLR_SURFACE, fg=CLR_ORANGE, font=("Segoe UI", 9),
            justify="left", anchor="w").grid(
                row=0, column=0, columnspan=3, sticky="we",
                padx=12, pady=(14, 8))

        self.enc_template_var = tk.StringVar()
        make_browse_row(parent, "Template .ffw (source of header/signature):",
                        self.enc_template_var, self._enc_browse_template, 1)

        self.enc_payload_var = tk.StringVar()
        make_browse_row(parent, "Payload ZIP (modified firmware):",
                        self.enc_payload_var, self._enc_browse_payload, 3)

        self.enc_output_var = tk.StringVar()
        make_browse_row(parent, "Output folder:",
                        self.enc_output_var, self._enc_browse_output, 5)

        self.enc_btn = make_button(parent, "🔒  Encrypt → .ffw",
                                    self._enc_start, CLR_ORANGE, height=2)
        self.enc_btn.grid(row=7, column=0, columnspan=3, sticky="we",
                          padx=12, pady=(20, 12))

    def _enc_browse_template(self):
        p = filedialog.askopenfilename(
            title="Select original .ffw (signature source)",
            filetypes=[("Firmware", "*.ffw"), ("All", "*.*")])
        if p:
            self.enc_template_var.set(p)
            if not self.enc_output_var.get():
                self.enc_output_var.set(os.path.dirname(p))

    def _enc_browse_payload(self):
        p = filedialog.askopenfilename(
            title="Select modified ZIP",
            filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
        if p:
            self.enc_payload_var.set(p)

    def _enc_browse_output(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.enc_output_var.set(p)

    def _enc_start(self):
        tmpl = self.enc_template_var.get().strip()
        pay  = self.enc_payload_var.get().strip()
        odir = self.enc_output_var.get().strip()

        if not tmpl or not os.path.isfile(tmpl):
            messagebox.showerror("Error", "Select a valid template .ffw.")
            return
        if not pay or not os.path.isfile(pay):
            messagebox.showerror("Error", "Select a valid payload ZIP.")
            return
        if not odir or not os.path.isdir(odir):
            messagebox.showerror("Error", "Select a valid output folder.")
            return

        if not messagebox.askyesno("Confirm",
            "This produces a firmware file reusing the original signature.\n"
            "Only flash on hardware you own.\n\nContinue?"):
            return

        base = os.path.splitext(os.path.basename(pay))[0]
        out = os.path.join(odir, base + ".repacked.ffw")

        self.enc_btn.config(state="disabled")
        self.progress["value"] = 0
        self._status("Encrypting…")
        threading.Thread(target=self._enc_run, args=(tmpl, pay, out),
                         daemon=True).start()

    def _enc_run(self, tmpl, pay, out):
        def cb(done, total):
            pct = int(done / total * 100) if total else 0
            self.root.after(0, lambda v=pct: self.progress.config(value=v))
        try:
            size = encrypt_ffw(tmpl, pay, out, progress_cb=cb)
            self.root.after(0, lambda: self._enc_done(out, size))
        except Exception as exc:
            msg = str(exc)
            self.root.after(0, lambda m=msg: self._enc_fail(m))

    def _enc_done(self, path, size):
        self.progress["value"] = 100
        self.enc_btn.config(state="normal")
        self._status(f"Encrypted → {os.path.basename(path)}  ({size:,} bytes)")
        messagebox.showinfo("Encrypt Complete",
            f"Repacked firmware saved to:\n\n{path}\n\n"
            f"{size:,} bytes\n\n"
            "Verify it decrypts correctly before flashing.")

    def _enc_fail(self, msg):
        self.enc_btn.config(state="normal")
        self._status("Encryption failed.")
        messagebox.showerror("Encrypt Failed", msg)

    # ──────────────────────────────────────────────────────────────────────
    #  Shared utilities
    # ──────────────────────────────────────────────────────────────────────

    def _status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_busy(self, busy):
        def _do():
            if busy:
                self.progress.config(mode="indeterminate")
                self.progress.start(12)
            else:
                self.progress.stop()
                self.progress.config(mode="determinate", value=0)
        self.root.after(0, _do)

    def cleanup(self):
        if self.work_dir and os.path.isdir(self.work_dir):
            shutil.rmtree(self.work_dir, ignore_errors=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    root = tk.Tk()
    app = FFWToolkit(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.cleanup(), root.destroy()))
    root.mainloop()
