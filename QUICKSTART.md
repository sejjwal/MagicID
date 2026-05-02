# ⚡ MagicID Quick Start Guide

Get up and running in under 5 minutes.

---

## 1. Prerequisites

- **Rust** 1.70 or newer  
  Install from: https://rustup.rs  
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

---

## 2. Build

```bash
git clone https://github.com/yourname/magicid.git
cd magicid
cargo build --release
```

The binary lands at `./target/release/magicid`.

---

## 3. Identify a file

```bash
./target/release/magicid identify /path/to/anyfile
```

Add `--hex` to see the raw header bytes:
```bash
./target/release/magicid identify /path/to/anyfile --hex
```

Add `--json` for machine-readable output:
```bash
./target/release/magicid identify /path/to/anyfile --json
```

---

## 4. Scan a directory

```bash
./target/release/magicid scan ./my_folder
```

Show **only mismatches** (suspicious files):
```bash
./target/release/magicid scan ./my_folder --mismatches-only
```

Limit scan depth and filter by category:
```bash
./target/release/magicid scan ./uploads --depth 3 --category executable
```

---

## 5. List the signature database

```bash
./target/release/magicid list
./target/release/magicid list --category archive
```

---

## 6. Install globally (optional)

```bash
cargo install --path .
# Now available as just: magicid
magicid identify myfile.pdf
```

---

## 7. Common Scenarios

### Validate upload safety
```bash
magicid scan ./user_uploads --mismatches-only
```

### Check a single suspicious file
```bash
magicid identify mystery_file --hex --json
```

### Audit a media folder
```bash
magicid scan ./media --category image
```

### Script integration (JSON pipeline)
```bash
magicid identify file.bin --json | jq '.detected.description'
```

---

## Supported Categories

| Category   | Examples                          |
|------------|-----------------------------------|
| Image      | JPG, PNG, GIF, WebP, BMP, TIFF   |
| Video      | MP4, MKV, AVI, FLV, WMV          |
| Audio      | MP3, WAV, FLAC, OGG, M4A         |
| Archive    | ZIP, RAR, GZ, 7Z, BZ2, XZ       |
| Document   | PDF, DOCX, DOC, RTF, HTML        |
| Executable | EXE, ELF, Mach-O, JAR, Shell    |
| Database   | SQLite3, MS Access               |
| Crypto     | PEM, DER, PGP                    |
| Disk Image | VHD, VMDK, QCOW2                 |

---

That's it! For full documentation see [README.md](README.md).
