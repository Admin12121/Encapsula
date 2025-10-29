<div align="center">

# 🔐 Encapsula

### Terminal-Based Steganography & Encryption Tool

[![NPM Version](https://img.shields.io/badge/version-1.1.4-orange.svg)](https://www.npmjs.com/package/encapsula)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2.2-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-red.svg)](#encryption-details)

**Hide encrypted messages inside any file — invisibly.**

[Features](#-features) • [Installation](#-installation) • [How It Works](#-how-it-works) • [Security](#-security-analysis) • [Roadmap](#-future-roadmap)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [How It Works](#-how-it-works)
  - [Encoding Process](#encoding-process-flowchart)
  - [Decoding Process](#decoding-process-flowchart)
  - [Encryption Details](#encryption-details)
  - [Steganography Methods](#steganography-methods)
- [Security Analysis](#-security-analysis)
- [Demo](#-demo)
- [Future Roadmap](#-future-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**Encapsula** is a terminal-based steganography tool that combines **AES-256-GCM authenticated encryption** with **adaptive LSB steganography** to hide secret messages inside ordinary files. Unlike traditional encryption that produces obvious encrypted files, Encapsula embeds your encrypted data within existing files (images, documents, executables, etc.), making the presence of hidden data nearly undetectable.

### Why Encapsula?

- 🔒 **Authenticated Encryption**: AES-256-GCM with built-in integrity verification
- 🧠 **Adaptive Key Derivation**: scrypt with memory-adaptive parameters (up to 2^15)
- 👁️ **Invisible Storage**: Messages hidden within normal files using LSB steganography
- 🎨 **Multi-Format Support**: PNG (LSB), JPEG (APP15), WebP (custom chunk), generic (trailer)
- 🔀 **Randomized Embedding**: HMAC-based PRNG for secure pixel positioning in PNGs
- 🚫 **Zero Password Storage**: Passwords never saved to disk
- 💻 **Beautiful Terminal UI**: Interactive command-line interface with progress tracking
- 🎯 **Simple Workflow**: Upload → Message → Password → Done

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **AES-256-GCM Encryption** | Authenticated encryption providing both confidentiality and integrity |
| **scrypt Key Derivation** | Memory-hard KDF with adaptive N (2^12 to 2^15) for brute-force resistance |
| **LSB Steganography** | Least Significant Bit embedding in PNG images with randomization |
| **Multi-Format Embedding** | PNG (LSB), JPEG (APP15 marker), WebP (chunk), generic files (trailer) |
| **Authenticated Encryption** | GCM mode provides cryptographic verification of data integrity |
| **Random Salt & IV** | Per-file cryptographic randomness prevents pattern analysis |
| **Adaptive Parameters** | Automatically adjusts to available system memory |
| **Multi-line Messages** | Support for complex, formatted secret messages |
| **Interactive TUI** | Terminal-based user interface with real-time progress tracking |
| **Cross-Platform** | Works on Windows, macOS, and Linux |
| **Secure Memory Handling** | Passwords cleared from memory after use |
| **Auto-Download** | Encoded files automatically copied to Downloads folder |

---

## 📦 Installation

### NPX (Recommended - No Installation)

```bash
npx encapsula
```

### Global Installation

```bash
npm install -g encapsula
encapsula
```

### From Source

```bash
git clone https://github.com/admin12121/Encapsula.git
cd Encapsula
npm install
npm run build
npm start
```

### Requirements

- Node.js 20 or higher
- Terminal with ANSI color support
- Minimum 128MB free RAM (512MB recommended for optimal scrypt parameters)

---

## 🚀 Quick Start

### Encoding (Hiding a Message)

1. **Launch Encapsula**
   ```bash
   npx encapsula
   ```

2. **Navigate to Encode Tab** (Press `Tab` key)

3. **Upload Host File** (Press `Enter`)
   - Select any file (PNG, JPEG, WebP, PDF, video, etc.)
   - For best steganography: use PNG images

4. **Enter Secret Message**
   - Type your multi-line message
   - Press `Ctrl+S` when finished

5. **Set Password**
   - Enter a strong password (minimum 8 characters recommended)
   - Press `Enter`

6. **Done!**
   - Encoded file saved to Downloads folder
   - Original file remains unchanged

### Decoding (Retrieving a Message)

1. **Navigate to Decode Tab** (Press `Tab`)

2. **Upload Encoded File**

3. **Enter Password** (same as encoding)

4. **View Decrypted Message**
   - Message displayed on screen
   - Optionally saved to .dec.txt file

---

## 🔍 How It Works

Encapsula uses a three-layer security approach: **key derivation** for password hardening, **authenticated encryption** for confidentiality and integrity, and **steganography** for concealment.

### Encoding Process Flowchart

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENCODING WORKFLOW                         │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │  User Input  │
    │  (Message +  │
    │  Password)   │
    └──────┬───────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  1. Generate Random Salt & IV            │
    │     • Salt: 16 random bytes              │
    │     • IV: 12 random bytes (GCM)          │
    │     • crypto.randomBytes() - CSPRNG      │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  2. Key Derivation (scrypt)              │
    │     • Password + Salt → scrypt KDF       │
    │     • Adaptive N: 2^15 → 2^12 (512MB mem)│
    │     • Parameters: r=8, p=1               │
    │     • Output: 32-byte AES-256 key        │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  3. Authenticated Encryption (AES-GCM)   │
    │     • Algorithm: AES-256-GCM             │
    │     • Input: plaintext message           │
    │     • Output: ciphertext + 16-byte tag   │
    │     • Tag verifies integrity             │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  4. Build 60-Byte Header                 │
    │     • Magic: "ECAP" (4)                  │
    │     • Version, flags, params (8)         │
    │     • Payload length (4)                 │
    │     • KDF params: kdf, logN, r, p (4)    │
    │     • Salt (16), IV (12), Tag (16)       │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  5. Format-Specific Embedding            │
    │                                          │
    │  ┌─ PNG: LSB Steganography              │
    │  │  • Header: LSB in first N pixels     │
    │  │  • Payload: randomized LSB positions │
    │  │  • HMAC-PRNG shuffles pixel indices  │
    │  │  • 1-2 bits per RGB channel          │
    │  │                                       │
    │  ┌─ JPEG: APP15 Marker Segment          │
    │  │  • Insert after SOI marker           │
    │  │  • Header + ciphertext in marker     │
    │  │                                       │
    │  ┌─ WebP: Custom Chunk                  │
    │  │  • Insert as WebP chunk              │
    │  │  • Follows WebP RIFF structure       │
    │  │                                       │
    │  └─ Other: Trailer Append                │
    │     • Signature: "ECAPTR" (6)           │
    │     • Length (4) + Header + Ciphertext  │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────┐
    │  Output File │
    │  (Carrier +  │
    │   Hidden)    │
    └──────────────┘
```

### Decoding Process Flowchart

```
┌─────────────────────────────────────────────────────────────────┐
│                        DECODING WORKFLOW                         │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │ Encoded File │
    └──────┬───────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  1. Detect Carrier Type & Extract Data   │
    │                                          │
    │  ┌─ PNG: LSB Extraction                 │
    │  │  • Read header from LSB bits         │
    │  │  • Parse randomization flag          │
    │  │  • Extract payload using HMAC-PRNG   │
    │  │                                       │
    │  ┌─ JPEG: Find APP15 Marker             │
    │  │  • Scan for APP15 segment            │
    │  │  • Extract header + ciphertext       │
    │  │                                       │
    │  ┌─ WebP: Find Custom Chunk             │
    │  │  • Parse WebP structure              │
    │  │  • Extract chunk data                │
    │  │                                       │
    │  └─ Other: Find Trailer                 │
    │     • Search for "ECAPTR" signature    │
    │     • Read length, extract payload     │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  2. Parse 60-Byte Header                 │
    │     • Verify magic: "ECAP"               │
    │     • Check version compatibility        │
    │     • Extract: salt, IV, tag, params     │
    │     • Read payload length                │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  3. Key Derivation (scrypt)              │
    │     • User password + extracted salt     │
    │     • Use stored logN, r, p parameters   │
    │     • Must match encoding key exactly    │
    │     • Output: 32-byte AES key            │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────────────────────────────────┐
    │  4. Authenticated Decryption (AES-GCM)   │
    │     • Use extracted IV and tag           │
    │     • Decrypt ciphertext                 │
    │     • Verify authentication tag          │
    │     • Fails if tampered/wrong password   │
    └──────┬───────────────────────────────────┘
           │
           ▼
    ┌──────────────┐
    │   Original   │
    │   Message    │
    │  (Plaintext) │
    └──────────────┘
```

### Encryption Details

#### 🔑 Key Derivation (scrypt)

Encapsula uses **scrypt**, a memory-hard key derivation function designed to resist hardware-accelerated brute-force attacks:

```
Password (User Input)
    ↓
Random 16-byte Salt (per file)
    ↓
scrypt(password, salt, N, r, p)
  • N = 2^logN (adaptive: 2^15 to 2^12)
  • r = 8 (block size)
  • p = 1 (parallelization)
  • maxmem = 512MB
    ↓
32-byte AES-256 Key
```

**Why scrypt over PBKDF2?**
- **Memory-Hard**: Requires significant RAM, making GPU/ASIC attacks expensive
- **Adaptive**: Automatically reduces N on memory-constrained systems
- **Strong Default**: N=2^15 (32,768 iterations) is ~32x stronger than typical PBKDF2
- **Time-Memory Tradeoff**: Attackers cannot trade time for memory

**Adaptive Algorithm:**
```
Try N = 2^15 (preferred)
  ↓
If memory error → reduce to 2^14
  ↓
If memory error → reduce to 2^13
  ↓
Continue until success (minimum 2^12)
```

The chosen logN is stored in the header, ensuring proper decryption.

#### 🔐 AES-256-GCM Authenticated Encryption

Encapsula uses **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and integrity:

```
Plaintext Message + Random 12-byte IV + 32-byte Key
    ↓
AES-256-GCM Encryption
    ↓
Ciphertext + 16-byte Authentication Tag
```

**AES-256-GCM Properties:**
- **Block Cipher**: AES with 256-bit key
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **IV Size**: 12 bytes (96 bits) - optimal for GCM
- **Tag Size**: 16 bytes (128 bits) - prevents tampering
- **Authentication**: Tag cryptographically verifies data integrity

**Security Benefits:**
- ✅ **Confidentiality**: Message content hidden from adversaries
- ✅ **Integrity**: Detects any modification to ciphertext
- ✅ **Authenticity**: Verifies data hasn't been tampered with
- ✅ **No Padding Oracles**: GCM is a stream cipher mode
- ✅ **Parallel Processing**: Faster than CBC mode

### Steganography Methods

Encapsula adapts its embedding strategy based on file type:

#### 📸 PNG: LSB Steganography with Randomization

For PNG images, Encapsula uses **Least Significant Bit (LSB)** embedding with optional randomization:

**Basic LSB Embedding:**
```
Original Pixel: RGB(11010110, 10110011, 01011010)
                    ↓       ↓       ↓
Embed 3 bits (1,0,1):
Modified Pixel: RGB(11010111, 10110010, 01011011)
                         ↑         ↑         ↑
                    (LSB changed to match data bits)
```

**Randomized Positioning (FLAG_RANDOMIZED):**
1. Generate HMAC-based PRNG from password
2. Shuffle pixel indices pseudo-randomly
3. Embed bits in shuffled order
4. Decoder uses same PRNG to reconstruct order

**Capacity Calculation:**
```
Header: 60 bytes × 8 bits = 480 bits (stored in first 480 LSBs)
Payload: Remaining RGB bytes × bits_per_channel
  • 1 bit/channel: capacity = (pixels × 3) - 480 bits
  • 2 bits/channel: capacity = (pixels × 6) - 480 bits
```

**Example:** 1920×1080 PNG (2,073,600 pixels)
- 1-bit mode: ~776 KB capacity
- 2-bit mode: ~1.5 MB capacity

#### 📷 JPEG: APP15 Marker Segment

JPEG format allows custom application-specific marker segments:

```
JPEG Structure:
[SOI][APP0 (JFIF)][...image data...][EOI]
          ↓
[SOI][APP15 (Encapsula)][APP0][...image data...][EOI]
       ↑
    Header + Ciphertext stored here
```

**Advantages:**
- ✅ Standard JPEG structure maintained
- ✅ Most viewers ignore unknown markers
- ✅ No visual artifacts
- ✅ Fast extraction (no pixel processing)

#### 🎞️ WebP: Custom Chunk

WebP uses a chunk-based RIFF container format:

```
WebP Structure:
RIFF[size][WEBP][VP8 ...][ALPH ...][EXIF ...]
                              ↓
RIFF[size][WEBP][VP8 ...][ECAP (Encapsula)][ALPH ...]
                           ↑
                    Custom chunk with payload
```

#### 📄 Generic Files: Trailer Append

For files without format-specific embedding:

```
[Original File Content][EOF]
                         ↓
[Original File Content][ECAPTR][Length][Header][Ciphertext][ECAPTR]
                         ↑                                     ↑
                   Start signature                       End signature
```

**Trailer Structure:**
```
Offset  | Size     | Description
--------|----------|-------------------------------------------
0       | 6 bytes  | Signature: "ECAPTR" (Encapsula Trailer)
6       | 4 bytes  | Payload length (Big Endian UInt32)
10      | 60 bytes | Header (salt, IV, tag, params)
70      | N bytes  | Ciphertext
70+N    | 6 bytes  | End signature: "ECAPTR"
```

**Why This Works:**
- Most programs ignore trailing data after EOF
- PDFs, executables, videos remain functional
- Large capacity (limited only by filesystem)
- Fast extraction via signature search

---

## 🛡️ Security Analysis

### What Makes It Secure

| Security Feature | Implementation | Benefit |
|-----------------|----------------|---------|
| **AES-256-GCM** | Authenticated encryption with 256-bit keys | Quantum-resistant symmetric encryption |
| **Random IVs** | crypto.randomBytes(12) per message | Prevents pattern analysis and replay attacks |
| **Random Salts** | crypto.randomBytes(16) per file | Prevents rainbow table attacks |
| **scrypt KDF** | Memory-hard with adaptive N (2^12–2^15) | Resists GPU/ASIC brute-force attacks |
| **Authentication Tag** | 128-bit GCM tag | Detects tampering and wrong passwords |
| **No Password Storage** | Cleared from memory post-use | No plaintext password leakage |
| **Steganographic Concealment** | Hidden within normal files | Reduces detection probability |
| **Randomized Embedding** | HMAC-PRNG for PNG positioning | Prevents statistical analysis |
| **Adaptive Security** | Adjusts to system capabilities | Balances security and compatibility |

### Cryptographic Strength

**Key Space:**
- AES-256: 2^256 possible keys (~10^77)
- Brute force time: Billions of years with current technology

**scrypt Parameters (N=2^15, r=8, p=1):**
- Memory required: ~64 MB per attempt
- Makes parallel attacks (GPU/ASIC) prohibitively expensive
- Estimated cost: >$1 million to crack a strong password

**GCM Authentication:**
- 128-bit tag provides 2^128 security against forgery
- Probability of successful random tag: 1 in 340 trillion trillion trillion

### Known Limitations & Mitigations

#### 1. **Password Strength Dependency**
**Issue**: Weak passwords reduce effective security  
**Mitigation**: 
- scrypt makes brute-force expensive even for moderate passwords
- Recommend 12+ character passwords with mixed case, numbers, symbols
- Tool does not enforce password policy (user responsibility)

#### 2. **Visual Capacity Limits**
**Issue**: High-capacity embedding in PNGs may cause subtle visual artifacts with 2-bit LSB  
**Mitigation**:
- Default to 1-bit mode for visual quality
- 2-bit mode only for large payloads
- Use JPEG/WebP/trailer for maximum stealth

#### 3. **File Format Preservation**
**Issue**: Some aggressive compression/optimization may strip hidden data  
**Risk**: JPEG re-encoding, PNG optimization, PDF compression  
**Mitigation**:
- Store backups of encoded files
- Verify integrity after file transfers
- Use lossless formats when possible

#### 4. **Metadata Leakage**
**Issue**: File modification timestamps may indicate alteration  
**Mitigation**:
- Not currently addressed in v1.x
- Planned for v2.0: timestamp preservation option

#### 5. **Memory Dumps**
**Issue**: Password strings may briefly exist in JavaScript heap  
**Risk**: Low (requires privileged system access during encoding)  
**Mitigation**:
- Passwords cleared immediately after use
- Future: Use secure buffer implementations

### Threat Model

**What Encapsula Protects Against:**
- ✅ Passive observers (steganography conceals existence)
- ✅ Brute-force attacks (scrypt + strong passwords)
- ✅ Rainbow tables (random salts)
- ✅ Data tampering (GCM authentication tags)
- ✅ Chosen-plaintext attacks (random IVs)
- ✅ Bit-flipping attacks (authenticated encryption)

**What Encapsula Does NOT Protect Against:**
- ❌ Weak user passwords (tool cannot force strong passwords)
- ❌ Keyloggers or malware (operating system security required)
- ❌ Targeted statistical analysis by experts (LSB has detectable patterns)
- ❌ Quantum computers (in far future, AES-256 remains strong)
- ❌ Social engineering (user must keep password secret)

---

## 📸 Demo

![Encapsula Demo](./assets/demo.png)

*Interactive terminal interface showing the encode/decode workflow*

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs** — Open an issue with reproduction steps
2. **Suggest Features** — Propose enhancements via GitHub Discussions
3. **Submit PRs** — Fix bugs or implement features
4. **Security Audits** — Help identify vulnerabilities (responsible disclosure)
5. **Documentation** — Improve guides, add examples
6. **Testing** — Write unit/integration tests

### Development Setup

```bash
# Clone repository
git clone https://github.com/admin12121/Encapsula.git
cd Encapsula

# Install dependencies
npm install
npm i --save-dev @types/pngjs

# Build TypeScript
npm run build

# Run in development mode
npm run dev

# Run production build
npm start
```

### Code Structure

```
Encapsula/
├── src/
│   ├── index.ts           # Entry point, tab navigation
│   ├── data.ts            # Configuration and constants
│   ├── loader.ts          # Startup/shutdown animations
│   ├── sections/
│   │   ├── home.ts        # Home screen with ASCII art
│   │   ├── encode.ts      # Encoding workflow (600+ lines)
│   │   └── decode.ts      # Decoding workflow (500+ lines)
│   ├── terminal/
│   │   ├── index.ts       # Terminal rendering and viewport
│   │   └── commands.ts    # Command processing
│   └── ui/
│       └── filePicker.ts  # File selection dialog
├── dist/                  # Compiled JavaScript (git ignored)
├── assets/                # Screenshots and media
├── package.json
├── tsconfig.json
└── README.md
```

### Running Tests (Coming Soon)

```bash
npm test
```

### Coding Standards

- TypeScript strict mode enabled
- ESLint for code quality
- Secure crypto practices (no hardcoded keys, proper RNG)
- Memory safety (buffer clearing, no leaks)
- Error handling (graceful degradation)

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 admin12121

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Disclaimer

**Encapsula is provided for educational and legitimate privacy purposes only.**

- ⚖️ This tool is **not** intended for illegal activities
- 👤 Users are responsible for compliance with local laws and regulations
- 🚫 The author assumes **no liability** for misuse or damages
- 🔐 Security depends on strong passwords and proper operational security
- 📊 No encryption is 100% unbreakable — use defense in depth

**Legal Notice:**
- Encryption laws vary by jurisdiction (check local regulations)
- Some countries restrict or ban cryptography without approval
- Export restrictions may apply in certain regions
- Corporate/enterprise use may require legal review

**Best Practices:**
- Use strong, unique passwords (12+ characters, mixed case, symbols)
- Keep software updated for latest security patches
- Store backups of important encoded files
- Do not reuse passwords across different files
- Securely delete original plaintext after encoding
- Verify file integrity after transfers

**Remember**: Security is a process, not a product. Always combine cryptographic tools with sound operational security practices.

---

## 🙏 Acknowledgments

- **Node.js Crypto Module** — For cryptographic primitives (AES, scrypt, HMAC)
- **terminal-kit** — For beautiful terminal UI rendering
- **pngjs** — For PNG parsing and manipulation
- **jpeg-js** — For JPEG format handling
- **Open Source Community** — For inspiration, tools, and security research
- **Cryptography Researchers** — For developing and analyzing scrypt, AES-GCM
- **InfoSec Community** — For responsible disclosure and security improvements

---

<div align="center">

**Made with ❤️ by [admin12121](https://github.com/admin12121)**

[![GitHub](https://img.shields.io/badge/GitHub-admin12121-181717?logo=github)](https://github.com/admin12121)
[![NPM](https://img.shields.io/badge/NPM-encapsula-CB3837?logo=npm)](https://www.npmjs.com/package/encapsula)

*Hiding in plain sight since 2024*

</div>