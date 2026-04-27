# MetaShield Enterprise v2.0

> **A zero-trust, browser-native forensic metadata sanitization engine.**

![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Runtime: Python--WASM](https://img.shields.io/badge/Runtime-Python--WASM-gold.svg)
![Dependencies: Zero](https://img.shields.io/badge/Dependencies-Zero--External-green.svg)
![Privacy: Client--Side Only](https://img.shields.io/badge/Privacy-Client--Side%20Only-blueviolet.svg)

---

## 1. The "Why" (Core Philosophy)

In the modern threat landscape, a file is never just its content. Every image, document, and media file carries a hidden payload of **Forensic Metadata**:
- **Geospatial Intelligence:** Exact GPS coordinates (latitude/longitude) of the capture location.
- **Hardware Signatures:** Device manufacturer, model, and unique serial numbers.
- **Organizational Exposure:** Embedded author names, software versions, and internal network paths.

Traditional sanitization tools introduce a secondary, often greater, risk: **Data Exfiltration**. Modern "online" tools require users to upload sensitive documents to remote servers for processing, breaking the chain of custody and compromising privacy. MetaShield Enterprise v2.0 solves this by moving the forensic laboratory directly into the browser's sandbox.

## 2. The "How" (Zero-Trust Architecture)

MetaShield implements a strictly serverless, zero-trust security model. No data ever leaves the local machine's volatile memory.

### WASM-Driven Execution
The engine leverages **Pyodide (Python 3.11 via WebAssembly)** to execute high-fidelity forensic libraries natively in the browser's hardware-accelerated sandbox. This allows for deep binary parsing that standard JavaScript cannot reliably perform.

### Dual-Engine Redundancy
1. **Primary Engine (Python-WASM):** Performs deep-packet inspection and structural rebuilds of complex file types (PDF, DOCX, MP4).
2. **Fallback Engine (JS Canvas):** A secondary, minimal logic layer used for rapid pixel-only image re-encoding should the WASM kernel be unavailable.

### Volatile RAM Persistence
Files are processed as `ArrayBuffer` objects within the browser's RAM. There is no intermediate disk caching, and all data is purged upon session termination or page refresh.

## 3. Forensic Capabilities

MetaShield is engineered for "Zero-Silent-Failure," ensuring every bit is accounted for.

*   **Polyglot Attack Detection:** The engine performs a real-time comparison between the declared MIME type and the actual **Magic Bytes** (file headers). Any discrepancy (e.g., an EXE masked as a JPEG) triggers a critical adversarial alert.
*   **Cryptographic Reverification:** Every file is hashed using **SHA-256** pre- and post-sanitization. This provides an immutable mathematical proof of the transformation.
*   **Adversarial Defense:**
    *   **Forensic Salting:** For corrupted media frames, the engine injects controlled null-bytes to force signature changes without compromising playback integrity.
    *   **Nuclear Metadata Destruction:** Images are not merely "cleaned"; they are rebuilt from raw pixel data into new binary blobs to ensure zero metadata leakage.
*   **5-Tier Format Support:**
    *   **Tier 1 (Images):** JPEG, PNG, TIFF, WEBP, GIF, BMP.
    *   **Tier 2 (Documents):** PDF (Structural rebuild), DOCX (Core property purge).
    *   **Tier 3 (Media):** MP4, MP3, WAV, FLAC, MKV (Atom/Tag stripping).
    *   **Tier 4 (Data):** CSV, JSON, XML (BOM stripping).
    *   **Tier 5 (Plaintext):** TXT (Encoding normalization).

## 4. Quick Start / Usage

MetaShield Enterprise is entirely portable and requires no backend infrastructure.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/VikashJakhar444/MetaShield-v2.git
    ```
2.  **Execution:**
    Open `index.html` in any modern, WASM-compliant browser (Chrome, Firefox, Edge, Safari).
3.  **No Build Steps:** No `npm install`, no `docker-compose`, and no server required.

## 5. Technical Stack

The forensic kernel utilizes industry-standard Python libraries compiled for WebAssembly:
-   `pypdf`: For PDF structural analysis and metadata purging.
-   `Pillow`: For deep image forensic extraction and pixel reconstruction.
-   `mutagen`: For aggressive media atom and tag destruction.
-   `python-docx`: For XML property sanitization in Word documents.

## 6. Audit & Evidence Export

Every action taken by the engine is logged with millisecond precision. Users can export:
-   **JSON Evidence Package:** A machine-readable forensic report containing pre/post hashes, detected threats, and an audit trail.
-   **TXT Audit Log:** A human-readable report suitable for court-admissible documentation of the sanitization process.

---

**Engineered by [Vikash Jakhar](https://github.com/VikashJakhar444)**  
*Distributed under the GNU General Public License v3.0. Built for privacy professionals and forensic analysts.*
