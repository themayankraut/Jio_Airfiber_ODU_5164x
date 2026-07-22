# FFW Firmware Toolkit

An all-in-one Graphical User Interface (GUI) and tool suite for decrypting, editing, and re-encrypting firmware files for Sercomm-based devices (specifically Jio ODU models) utilizing the `.ffw` container format.

The toolkit allows you to modify internal software/hardware version parameters in the device's filesystem (`sysfs` / `oem` UBIFS volumes) and cleanly repack them with automatically updated checksums and sizes, enabling testing and analysis of custom configurations.

---

## Features

- **Tab 1: Decrypt** 
  - Parses `.ffw` headers.
  - Automatically derives keys via SHA-256 hash validation of the signature block.
  - Decrypts chunked AES-256-CBC ciphertext into a standard, inspectable `.zip` archive.
- **Tab 2: Edit Parameters**
  - Auto-scans decrypted firmware layout (detects bare UBIFS `sysfs.ubifs` or UBI containers `sysfs.ubi`).
  - Reads UBIFS superblock parameters (min I/O, LEB size, compression algorithm) automatically.
  - Extracts and parses device configurations from `/usr/etc/versions`.
  - Provides a clean interface to edit hardware versions, software versions, build parameters, and vendor properties.
  - Repacks filesystem structures via a local environment or WSL using `mkfs.ubifs` and `ubinize` with matching geometry parameters.
  - **Auto-Calculates Integrity Checks**: Automatically updates MD5 partition hashes and byte lengths in `updater_script` to match the modified filesystem.
- **Tab 3: Encrypt**
  - Re-encrypts the modified firmware ZIP payload back into the `.ffw` container.
  - Preserves the authentic outer header structure from a template `.ffw` firmware.

---

## Technical Architecture & Mechanics

### 1. The `.ffw` Container Format
The firmware uses a structured binary format:
```
+---------------------------+-----------------------------------+
| Magic Header (8 bytes)    | 0x43724573 0x216d4d6f             |
+---------------------------+-----------------------------------+
| Signed Block (824 bytes)  | RSA Signed metadata, contains IV  |
+---------------------------+-----------------------------------+
| Encrypted Payload         | Chunked AES-256-CBC ciphertext    |
+---------------------------+-----------------------------------+
| Trailer (32 bytes)        | SHA-256 checksum of payload       |
+---------------------------+-----------------------------------+
```
- **AES Key Generation**: Calculated dynamically by applying a SHA-256 hash to the signature block (offset `0x08` to `0x340`).
- **Initialization Vector (IV)**: Resides inside the signature block at offset `0x330`.
- **Chunking Mechanism**: The plaintext zip file is chunked into 64KB (`0x10000` bytes) blocks. Each block is individually padded via PKCS7 and encrypted into `0x10010` byte ciphertext chunks.

### 2. Filesystem Repacking (UBI/UBIFS)
The toolkit supports both formats:
* **Bare UBIFS (`.ubifs`)**: Extracted and repacked using `mkfs.ubifs` matching the original block geometries.
* **UBI Containers (`.ubi`)**: The toolkit parses internal volume tables, extracts individual raw UBIFS volumes, and builds a configuration file for `ubinize` to ensure the structure matches the original layout when repacking.

---

## License & Disclaimer
This software is provided for educational and diagnostic purposes only. It is intended solely for security research, analysis, and custom development on hardware owned by the user. Modifying and flashing firmware carries inherent risks of bricking hardware devices. The authors are not responsible for any damage, loss of service, or hardware failure resulting from the use of this software.
