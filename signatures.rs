/// Magic number signatures database
/// Each entry: (offset, magic_bytes, extension, mime_type, description)

#[derive(Debug, Clone)]
pub struct Signature {
    pub offset: usize,
    pub magic: &'static [u8],
    pub extension: &'static str,
    pub mime_type: &'static str,
    pub description: &'static str,
    pub category: Category,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Category {
    Image,
    Video,
    Audio,
    Archive,
    Document,
    Executable,
    Database,
    Crypto,
    Disk,
    Other,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Image    => write!(f, "Image"),
            Category::Video    => write!(f, "Video"),
            Category::Audio    => write!(f, "Audio"),
            Category::Archive  => write!(f, "Archive"),
            Category::Document => write!(f, "Document"),
            Category::Executable => write!(f, "Executable"),
            Category::Database => write!(f, "Database"),
            Category::Crypto   => write!(f, "Crypto"),
            Category::Disk     => write!(f, "Disk Image"),
            Category::Other    => write!(f, "Other"),
        }
    }
}

pub fn get_signatures() -> Vec<Signature> {
    vec![
        // ── Images ──────────────────────────────────────────────────────────
        Signature { offset: 0, magic: &[0xFF, 0xD8, 0xFF], extension: "jpg", mime_type: "image/jpeg", description: "JPEG Image", category: Category::Image },
        Signature { offset: 0, magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], extension: "png", mime_type: "image/png", description: "PNG Image", category: Category::Image },
        Signature { offset: 0, magic: b"GIF87a", extension: "gif", mime_type: "image/gif", description: "GIF Image (87a)", category: Category::Image },
        Signature { offset: 0, magic: b"GIF89a", extension: "gif", mime_type: "image/gif", description: "GIF Image (89a)", category: Category::Image },
        Signature { offset: 0, magic: b"RIFF", extension: "webp", mime_type: "image/webp", description: "WebP Image", category: Category::Image },
        Signature { offset: 0, magic: &[0x42, 0x4D], extension: "bmp", mime_type: "image/bmp", description: "BMP Image", category: Category::Image },
        Signature { offset: 0, magic: &[0x49, 0x49, 0x2A, 0x00], extension: "tif", mime_type: "image/tiff", description: "TIFF Image (little-endian)", category: Category::Image },
        Signature { offset: 0, magic: &[0x4D, 0x4D, 0x00, 0x2A], extension: "tif", mime_type: "image/tiff", description: "TIFF Image (big-endian)", category: Category::Image },
        Signature { offset: 0, magic: &[0x00, 0x00, 0x01, 0x00], extension: "ico", mime_type: "image/x-icon", description: "Windows Icon", category: Category::Image },
        Signature { offset: 0, magic: b"8BPS", extension: "psd", mime_type: "image/vnd.adobe.photoshop", description: "Adobe Photoshop", category: Category::Image },

        // ── Video ────────────────────────────────────────────────────────────
        Signature { offset: 0, magic: &[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], extension: "mp4", mime_type: "video/mp4", description: "MPEG-4 Video", category: Category::Video },
        Signature { offset: 0, magic: &[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], extension: "mp4", mime_type: "video/mp4", description: "MPEG-4 Video", category: Category::Video },
        Signature { offset: 4,  magic: b"ftyp", extension: "mp4", mime_type: "video/mp4", description: "MPEG-4 Video (ftyp)", category: Category::Video },
        Signature { offset: 0, magic: &[0x1A, 0x45, 0xDF, 0xA3], extension: "mkv", mime_type: "video/x-matroska", description: "Matroska Video (MKV/WebM)", category: Category::Video },
        Signature { offset: 0, magic: b"RIFF", extension: "avi", mime_type: "video/x-msvideo", description: "AVI Video", category: Category::Video },
        Signature { offset: 0, magic: &[0x00, 0x00, 0x01, 0xB3], extension: "mpg", mime_type: "video/mpeg", description: "MPEG Video", category: Category::Video },
        Signature { offset: 0, magic: &[0x00, 0x00, 0x01, 0xBA], extension: "mpg", mime_type: "video/mpeg", description: "MPEG Video (PS)", category: Category::Video },
        Signature { offset: 0, magic: b"FLV\x01", extension: "flv", mime_type: "video/x-flv", description: "Flash Video", category: Category::Video },
        Signature { offset: 0, magic: &[0x30, 0x26, 0xB2, 0x75], extension: "wmv", mime_type: "video/x-ms-wmv", description: "Windows Media Video", category: Category::Video },

        // ── Audio ────────────────────────────────────────────────────────────
        Signature { offset: 0, magic: &[0xFF, 0xFB], extension: "mp3", mime_type: "audio/mpeg", description: "MP3 Audio", category: Category::Audio },
        Signature { offset: 0, magic: b"ID3",  extension: "mp3", mime_type: "audio/mpeg", description: "MP3 Audio (ID3)", category: Category::Audio },
        Signature { offset: 0, magic: b"RIFF", extension: "wav", mime_type: "audio/wav", description: "WAV Audio", category: Category::Audio },
        Signature { offset: 0, magic: b"fLaC", extension: "flac", mime_type: "audio/flac", description: "FLAC Audio", category: Category::Audio },
        Signature { offset: 0, magic: b"OggS", extension: "ogg", mime_type: "audio/ogg", description: "OGG Audio", category: Category::Audio },
        Signature { offset: 0, magic: b"M4A ", extension: "m4a", mime_type: "audio/mp4", description: "M4A Audio", category: Category::Audio },
        Signature { offset: 0, magic: &[0x30, 0x26, 0xB2, 0x75], extension: "wma", mime_type: "audio/x-ms-wma", description: "Windows Media Audio", category: Category::Audio },

        // ── Archives ─────────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"PK\x03\x04", extension: "zip", mime_type: "application/zip", description: "ZIP Archive", category: Category::Archive },
        Signature { offset: 0, magic: b"PK\x05\x06", extension: "zip", mime_type: "application/zip", description: "ZIP Archive (empty)", category: Category::Archive },
        Signature { offset: 0, magic: b"PK\x07\x08", extension: "zip", mime_type: "application/zip", description: "ZIP Archive (spanned)", category: Category::Archive },
        Signature { offset: 0, magic: b"Rar!", extension: "rar", mime_type: "application/x-rar-compressed", description: "RAR Archive", category: Category::Archive },
        Signature { offset: 0, magic: &[0x1F, 0x8B], extension: "gz",  mime_type: "application/gzip", description: "GZIP Archive", category: Category::Archive },
        Signature { offset: 0, magic: &[0x42, 0x5A, 0x68], extension: "bz2", mime_type: "application/x-bzip2", description: "BZIP2 Archive", category: Category::Archive },
        Signature { offset: 0, magic: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], extension: "xz", mime_type: "application/x-xz", description: "XZ Archive", category: Category::Archive },
        Signature { offset: 0, magic: b"7z\xBC\xAF\x27\x1C", extension: "7z", mime_type: "application/x-7z-compressed", description: "7-Zip Archive", category: Category::Archive },
        Signature { offset: 0, magic: b"ustar", extension: "tar", mime_type: "application/x-tar", description: "TAR Archive", category: Category::Archive },
        Signature { offset: 0, magic: &[0x1F, 0x9D], extension: "z",  mime_type: "application/x-compress", description: "Z Compressed Archive", category: Category::Archive },

        // ── Documents ────────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"%PDF", extension: "pdf", mime_type: "application/pdf", description: "PDF Document", category: Category::Document },
        Signature { offset: 0, magic: b"PK\x03\x04", extension: "docx", mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", description: "Microsoft Word (OOXML)", category: Category::Document },
        Signature { offset: 0, magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], extension: "doc", mime_type: "application/msword", description: "Microsoft Office (OLE2)", category: Category::Document },
        Signature { offset: 0, magic: b"\xEF\xBB\xBF", extension: "txt", mime_type: "text/plain", description: "UTF-8 Text with BOM", category: Category::Document },
        Signature { offset: 0, magic: b"<?xml", extension: "xml", mime_type: "application/xml", description: "XML Document", category: Category::Document },
        Signature { offset: 0, magic: b"<!DOCTYPE html", extension: "html", mime_type: "text/html", description: "HTML Document", category: Category::Document },
        Signature { offset: 0, magic: b"<html", extension: "html", mime_type: "text/html", description: "HTML Document", category: Category::Document },
        Signature { offset: 0, magic: b"{\\rtf", extension: "rtf", mime_type: "application/rtf", description: "Rich Text Format", category: Category::Document },

        // ── Executables ──────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"MZ",   extension: "exe", mime_type: "application/x-msdownload", description: "Windows Executable (PE)", category: Category::Executable },
        Signature { offset: 0, magic: &[0x7F, 0x45, 0x4C, 0x46], extension: "elf", mime_type: "application/x-elf", description: "ELF Executable (Linux/Unix)", category: Category::Executable },
        Signature { offset: 0, magic: &[0xFE, 0xED, 0xFA, 0xCE], extension: "macho", mime_type: "application/x-mach-binary", description: "Mach-O Binary (32-bit)", category: Category::Executable },
        Signature { offset: 0, magic: &[0xFE, 0xED, 0xFA, 0xCF], extension: "macho", mime_type: "application/x-mach-binary", description: "Mach-O Binary (64-bit)", category: Category::Executable },
        Signature { offset: 0, magic: &[0xCE, 0xFA, 0xED, 0xFE], extension: "macho", mime_type: "application/x-mach-binary", description: "Mach-O Binary (reverse 32-bit)", category: Category::Executable },
        Signature { offset: 0, magic: &[0xCA, 0xFE, 0xBA, 0xBE], extension: "class", mime_type: "application/java-vm", description: "Java Class File / Mach-O Fat Binary", category: Category::Executable },
        Signature { offset: 0, magic: b"#!/", extension: "sh", mime_type: "text/x-shellscript", description: "Unix Shell Script", category: Category::Executable },
        Signature { offset: 0, magic: b"#!", extension: "sh", mime_type: "text/x-shellscript", description: "Unix Script (shebang)", category: Category::Executable },

        // ── Databases ────────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"SQLite format 3\x00", extension: "db", mime_type: "application/x-sqlite3", description: "SQLite3 Database", category: Category::Database },
        Signature { offset: 0, magic: &[0x00, 0x01, 0x00, 0x00, 0x4D, 0x53, 0x4D, 0x44], extension: "mdb", mime_type: "application/x-msaccess", description: "MS Access Database", category: Category::Database },

        // ── Crypto / Keys ────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"-----BEGIN", extension: "pem", mime_type: "application/x-pem-file", description: "PEM Certificate/Key", category: Category::Crypto },
        Signature { offset: 0, magic: &[0x30, 0x82], extension: "der", mime_type: "application/x-x509-ca-cert", description: "DER Certificate", category: Category::Crypto },
        Signature { offset: 0, magic: b"PGP\x20PUBLIC", extension: "asc", mime_type: "application/pgp-keys", description: "PGP Public Key", category: Category::Crypto },

        // ── Disk Images ──────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"conectix", extension: "vhd", mime_type: "application/x-vhd", description: "VirtualPC VHD Disk", category: Category::Disk },
        Signature { offset: 0, magic: b"KDMV", extension: "vmdk", mime_type: "application/x-vmdk", description: "VMware Disk Image", category: Category::Disk },
        Signature { offset: 0, magic: &[0x51, 0x46, 0x49, 0xFB], extension: "qcow2", mime_type: "application/x-qemu-disk", description: "QEMU QCOW2 Disk Image", category: Category::Disk },

        // ── Other ────────────────────────────────────────────────────────────
        Signature { offset: 0, magic: b"caff", extension: "pcap", mime_type: "application/vnd.tcpdump.pcap", description: "PCAP Network Capture", category: Category::Other },
        Signature { offset: 0, magic: &[0xD4, 0xC3, 0xB2, 0xA1], extension: "pcap", mime_type: "application/vnd.tcpdump.pcap", description: "PCAP Network Capture (LE)", category: Category::Other },
        Signature { offset: 0, magic: &[0x0A, 0x0D, 0x0D, 0x0A], extension: "pcapng", mime_type: "application/x-pcapng", description: "PCAPng Network Capture", category: Category::Other },
        Signature { offset: 0, magic: b"\x1FLua", extension: "luac", mime_type: "application/x-lua-bytecode", description: "Lua Bytecode", category: Category::Other },
        Signature { offset: 0, magic: &[0x1F, 0x8B], extension: "nupkg", mime_type: "application/zip", description: "NuGet Package", category: Category::Other },
    ]
}
