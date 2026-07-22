# Requirements and Setup Guide

This guide details the system requirements and environment setup necessary to run the FFW Firmware Toolkit and use its filesystem repacking features.

## 1. Operating System
- **Host OS**: Windows 10 or Windows 11 (64-bit).
- **WSL (Windows Subsystem for Linux)**: Required to rebuild and compress the UBIFS/UBI partitions.

---

## 2. Python Dependencies (Windows Host)
Make sure you have **Python 3.8 or higher** installed.

Install the required Python packages:
```
pip install pycryptodome ubi_reader
```

| Package | Version | Purpose |
|---|---|---|
| `pycryptodome` | >= 3.10.0 | AES-256-CBC encryption and decryption of `.ffw` payloads |
| `ubi-reader` | >= 0.8.0 | Parsing and extracting UBIFS/UBI filesystem images |

---

## 3. Repack Environment Setup (WSL Backend)
Because Linux-based utilities (`mkfs.ubifs` and `ubinize`) are required to package flash filesystems, you must set up a WSL environment.

### Step 1 — Install WSL
Open PowerShell as Administrator and run:
```
wsl --install
```
Restart your computer if prompted.

### Step 2 — Install Filesystem Utilities in WSL
Open your installed Linux/Ubuntu terminal and run:
```
sudo apt update
sudo apt install -y mtd-utils python3-pip
```

### Step 3 — Install ubi_reader in WSL
Run the following inside the WSL terminal:
```
pip3 install --break-system-packages ubi_reader
```

Once these steps are complete, the toolkit's Tab 2 (Save & Repack) will seamlessly execute operations through WSL.

---

## 4. Verification
To verify your setup is correct, open a Windows terminal and run:
```
python -c "from Crypto.Cipher import AES; print('pycryptodome OK')"
wsl bash -c "which mkfs.ubifs && echo 'mkfs.ubifs OK'"
wsl bash -c "which ubireader_extract_files && echo 'ubireader OK'"
```
All three checks should print OK.
