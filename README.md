# 🔍 MagicID — Magic Number File Type Identifier

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Crate](https://img.shields.io/badge/crate-magicid-red.svg)](https://crates.io)

> Identify **true file types** by their magic bytes — not their extensions.  
> Detect disguised malware, validate uploads, and audit directories in milliseconds.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **60+ signatures** | Images, video, audio, archives, docs, executables, crypto, disk images |
| ⚠️ **Mismatch detection** | Flags files whose extension doesn't match their actual type |
| 📁 **Directory scanning** | Recursive scan with depth control and category filters |
| 🎨 **Colored output** | Clear, readable terminal output |
| 📦 **JSON output** | Machine-readable output for scripting pipelines |
| ⚡ **Blazing fast** | Reads only the first 512 bytes per file |

---

## 🚀 Installation

### From source (requires Rust + Cargo)

```bash
git clone https://github.com/yourname/magicid.git
cd magicid
cargo build --release
# Binary at: ./target/release/magicid
```

### Install globally

```bash
cargo install --path .
```

---

## 📖 Usage

### Identify a single file

```bash
magicid identify photo.jpg
magicid identify suspicious.exe --hex        # show hex header
magicid identify document.pdf --json         # JSON output
```

### Scan a directory

```bash
magicid scan ./uploads                        # scan all files
magicid scan ./uploads --mismatches-only      # only show suspicious files
magicid scan ./files --depth 2               # limit recursion depth
magicid scan ./media --category image        # filter by category
```

### List all known signatures

```bash
magicid list
magicid list --category archive
```

---

## 🎯 Example Output

```
File:     ./test_files/fake_image.exe
Size:     72.00 KB
Type:     Windows Executable (PE)
Category: Executable
True Ext: .exe

⚠  MISMATCH: Extension .jpg does not match detected type .exe
```

---

## 🔬 How It Works

Every file format reserves a specific sequence of bytes at a known offset — called a **magic number** or **file signature**. For example:

| Format | Offset | Magic Bytes (Hex) |
|--------|--------|-------------------|
| PNG    | 0      | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG   | 0      | `FF D8 FF` |
| ZIP    | 0      | `50 4B 03 04` |
| ELF    | 0      | `7F 45 4C 46` |
| PDF    | 0      | `25 50 44 46` |

MagicID reads the first 512 bytes of a file, matches them against its database, and reports the true type — regardless of the filename or extension.

---

## 🛡️ Security Use Cases

- **Upload validation** — Ensure users aren't disguising `.exe` as `.jpg`
- **Malware triage** — Quick first-pass identification of suspicious binaries
- **Forensics** — Identify files with stripped or tampered headers
- **CI/CD pipelines** — Validate build artifacts have correct types

---

## 📂 Project Structure

```
magicid/
├── Cargo.toml
├── README.md
├── QUICKSTART.md
└── src/
    ├── main.rs          # CLI interface (clap)
    ├── analyzer.rs      # File reading & matching logic
    └── signatures.rs    # Magic number database (60+ entries)
```

---

## 🧩 Adding Custom Signatures

Open `src/signatures.rs` and add an entry to the `get_signatures()` vector:

```rust
Signature {
    offset: 0,
    magic: &[0xAB, 0xCD, 0xEF],
    extension: "xyz",
    mime_type: "application/x-xyz",
    description: "My Custom Format",
    category: Category::Other,
},
```

Rebuild with `cargo build --release` — done!

---

## 📜 License

MIT © 2024 MagicID Project
