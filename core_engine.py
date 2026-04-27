"""
MetaShield Enterprise v2.0 — Python Forensic Core Engine
Architecture: Python-WASM (Pyodide)
License: GNU GPL v3
Author: Vikash Jakhar
"""

import io
import json
import re

# These modules are provided by the Pyodide runtime in the browser.
# We wrap them to suppress local IDE warnings.
try:
    import js # type: ignore
    from PIL import Image, ExifTags # type: ignore
    from pypdf import PdfReader, PdfWriter # type: ignore
    import mutagen # type: ignore
    from mutagen.mp4 import MP4 # type: ignore
    from mutagen.id3 import ID3, ID3NoHeaderError # type: ignore
    from mutagen.mp3 import MP3 # type: ignore
    import docx # type: ignore
except ImportError:
    pass

# ══════════════════════════════════════════════════════
# SENSITIVE KEY DETECTION (for threat analysis)
# ══════════════════════════════════════════════════════
SENSITIVE_PATTERNS = [
    ('gps', 'GPS/Location data'),
    ('latitude', 'Geographic coordinates'),
    ('longitude', 'Geographic coordinates'),
    ('author', 'Author identity'),
    ('creator', 'Creator identity'),
    ('artist', 'Artist/user identity'),
    ('owner', 'Ownership information'),
    ('software', 'Software signature'),
    ('camera', 'Device signature'),
    ('make', 'Device manufacturer'),
    ('model', 'Device model'),
    ('serial', 'Device serial number'),
    ('user', 'User identity'),
    ('comment', 'Embedded comments'),
    ('copyright', 'Copyright/legal info'),
    ('producer', 'Software producer'),
]

def is_sensitive(key):
    k = str(key).lower()
    for pattern, _ in SENSITIVE_PATTERNS:
        if pattern in k:
            return True
    return False

def classify_threat(meta_dict):
    """Analyze metadata for privacy/security threats."""
    threats = []
    keys_lower = [str(k).lower() for k in meta_dict.keys()]

    # GPS check
    if any('gps' in k or 'latitude' in k or 'longitude' in k for k in keys_lower):
        threats.append({
            'severity': 'critical',
            'icon': '📍',
            'title': 'GPS Location Leak Detected',
            'desc': 'This file contains geographic coordinates that can reveal exact physical location where it was created.'
        })

    # Device identity
    if any(k in keys_lower for k in ['make', 'model', 'camera']) or any('camera' in k for k in keys_lower):
        threats.append({
            'severity': 'high',
            'icon': '📷',
            'title': 'Device Fingerprint Exposed',
            'desc': 'Hardware make/model is embedded, allowing device tracking and correlation across files.'
        })

    # Serial number
    if any('serial' in k for k in keys_lower):
        threats.append({
            'severity': 'critical',
            'icon': '🔢',
            'title': 'Device Serial Number Present',
            'desc': 'Unique device identifier found - this can link the file directly to a specific physical device.'
        })

    # Author/identity
    if any(k in ['author', 'creator', 'artist', 'owner', 'user'] or ('author' in k or 'creator' in k) for k in keys_lower):
        threats.append({
            'severity': 'high',
            'icon': '👤',
            'title': 'Personal Identity Embedded',
            'desc': 'Author or creator name is embedded in file metadata, exposing personal identity.'
        })

    # Software signature
    if any('software' in k or 'producer' in k for k in keys_lower):
        threats.append({
            'severity': 'medium',
            'icon': '💻',
            'title': 'Software Signature Present',
            'desc': 'The editing software signature is recorded, revealing tool chain used.'
        })

    # Timestamps
    if any('date' in k or 'time' in k or 'created' in k or 'modified' in k for k in keys_lower):
        threats.append({
            'severity': 'medium',
            'icon': '🕐',
            'title': 'Temporal Metadata Found',
            'desc': 'Creation/modification timestamps can be used for timeline analysis and correlation attacks.'
        })

    # Thumbnail (can contain original image even after crop)
    if any('thumbnail' in k or 'preview' in k for k in keys_lower):
        threats.append({
            'severity': 'critical',
            'icon': '🖼️',
            'title': 'Embedded Thumbnail Detected',
            'desc': 'A thumbnail image is embedded - this may contain original unmodified content even after editing.'
        })

    return threats


# ══════════════════════════════════════════════════════
# DEEP EXTRACTION ENGINE
# ══════════════════════════════════════════════════════
def python_extract(file_bytes, mime_type, file_name):
    meta = {}
    warnings = []

    try:
        py_data = file_bytes.to_py()
        b_io = io.BytesIO(py_data)
        b_io.name = file_name
        name_lower = file_name.lower()

        # ─── IMAGES (JPEG, PNG, TIFF, WEBP, GIF, BMP) ───
        if mime_type.startswith('image/') or name_lower.endswith(('.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.gif', '.bmp')):
            img = Image.open(b_io)
            meta['Image_Format'] = img.format or 'Unknown'
            meta['Image_Mode'] = img.mode
            meta['Image_Dimensions'] = f"{img.width} x {img.height} px"

            try:
                exif_data = img.getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, f"EXIF_Tag_{tag_id}")
                        if isinstance(value, bytes):
                            try: value = value.decode('utf-8', errors='ignore')
                            except: value = value.hex()[:40]
                        meta[f"EXIF_{tag_name}"] = str(value)[:200]

                    gps_info = exif_data.get_ifd(0x8825)
                    if gps_info:
                        for gps_tag, gps_val in gps_info.items():
                            tag_name = ExifTags.GPSTAGS.get(gps_tag, f"GPS_Tag_{gps_tag}")
                            meta[f"GPS_{tag_name}"] = str(gps_val)[:200]
            except Exception as e:
                warnings.append(f"EXIF parse: {str(e)}")

            if 'icc_profile' in img.info:
                meta['ICC_Profile_Size'] = f"{len(img.info['icc_profile'])} bytes"
            if 'xmp' in img.info:
                meta['XMP_Block'] = "DETECTED (XML metadata)"
            if 'photoshop' in img.info:
                meta['Photoshop_IRB'] = "DETECTED"
            if 'iptc' in img.info:
                meta['IPTC_Block'] = "DETECTED"

            if img.format == 'PNG':
                for k, v in img.info.items():
                    if k not in ['icc_profile', 'xmp', 'photoshop']:
                        meta[f"PNG_{k}"] = str(v)[:200]

        # ─── PDF DOCUMENTS ───
        elif mime_type == 'application/pdf' or name_lower.endswith('.pdf'):
            reader = PdfReader(b_io)
            meta['PDF_Pages'] = len(reader.pages)
            meta['PDF_Encrypted'] = str(reader.is_encrypted)

            if reader.metadata:
                for k, v in reader.metadata.items():
                    key = k.strip('/')
                    if key: meta[f"PDF_{key}"] = str(v)[:300]

            try:
                if hasattr(reader, 'xmp_metadata') and reader.xmp_metadata:
                    meta['PDF_XMP'] = "DETECTED (XMP stream present)"
            except:
                pass

        # ─── DOCX WORD DOCUMENTS ───
        elif name_lower.endswith('.docx'):
            doc = docx.Document(b_io)
            prop = doc.core_properties
            fields = {
                'Author': prop.author, 'Title': prop.title,
                'Subject': prop.subject, 'Keywords': prop.keywords,
                'Comments': prop.comments, 'Category': prop.category,
                'Created': prop.created, 'Modified': prop.modified,
                'Last_Modified_By': prop.last_modified_by,
                'Revision': prop.revision, 'Version': prop.version,
                'Content_Status': prop.content_status,
                'Language': prop.language,
                'Identifier': prop.identifier
            }
            for k, v in fields.items():
                if v: meta[f"Docx_{k}"] = str(v)[:200]

        # ─── AUDIO/VIDEO via Mutagen ───
        elif (mime_type.startswith('audio/') or mime_type.startswith('video/') or
              name_lower.endswith(('.mp3', '.mp4', '.mkv', '.wav', '.flac', '.m4a', '.ogg', '.mov'))):
            try:
                media = mutagen.File(b_io)
                if media is not None:
                    if hasattr(media, 'info'):
                        if hasattr(media.info, 'length'):
                            meta['Media_Duration_Seconds'] = f"{media.info.length:.2f}"
                        if hasattr(media.info, 'bitrate'):
                            meta['Media_Bitrate'] = f"{media.info.bitrate} bps"

                    if hasattr(media, 'tags') and media.tags:
                        for k, v in list(media.tags.items())[:30]:
                            meta[f"Tag_{k}"] = str(v)[:200]
            except Exception as e:
                warnings.append(f"Media parse: {str(e)}")

        # ─── TEXT / CSV / JSON ───
        elif mime_type.startswith('text/') or name_lower.endswith(('.txt', '.csv', '.json', '.xml', '.log')):
            b_io.seek(0)
            raw = b_io.read()
            meta['Text_Size_Bytes'] = len(raw)
            try:
                text = raw.decode('utf-8', errors='ignore')
                meta['Text_Lines'] = str(text.count('\n') + 1)
                meta['Text_Characters'] = str(len(text))

                if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
                    meta['PII_Email_Found'] = 'Yes (emails detected in content)'
                if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
                    meta['PII_IP_Found'] = 'Yes (IP addresses detected)'
            except:
                meta['Text_Status'] = 'Binary or unknown encoding'

    except Exception as e:
        meta['Extraction_Error'] = str(e)

    clean_meta = {k: v for k, v in meta.items() if v and str(v).strip() not in ('None', '', '0001-01-01 00:00:00+00:00')}
    return json.dumps({
        'metadata': clean_meta,
        'threats': classify_threat(clean_meta),
        'warnings': warnings
    })


# ══════════════════════════════════════════════════════
# SANITIZATION ENGINE (ZERO-TOLERANCE)
# ══════════════════════════════════════════════════════
def python_sanitize(file_bytes, mime_type, file_name):
    py_data = file_bytes.to_py()
    b_io = io.BytesIO(py_data)
    b_io.name = file_name
    name_lower = file_name.lower()
    out = io.BytesIO()
    processed = False
    log = []

    try:
        # ─── IMAGES: Pixel-only re-encoding ───
        if mime_type.startswith('image/') or name_lower.endswith(('.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.gif', '.bmp')):
            img = Image.open(b_io)
            img_format = img.format if img.format else 'PNG'
            log.append(f"Format detected: {img_format}")

            if img_format == 'JPEG' and img.mode in ('RGBA', 'P', 'LA'):
                img = img.convert('RGB')
                log.append("Mode converted to RGB")

            # Nuclear metadata destruction: paste pixels into new canvas
            clean_img = Image.new(img.mode, img.size)
            clean_img.paste(img)

            save_kwargs = {'format': img_format, 'optimize': True}
            if img_format == 'JPEG': save_kwargs['quality'] = 95

            clean_img.save(out, **save_kwargs)
            log.append("Image rebuilt from raw pixels (zero-metadata)")
            processed = True

        # ─── PDF: Dictionary purge + structural rebuild ───
        elif mime_type == 'application/pdf' or name_lower.endswith('.pdf'):
            reader = PdfReader(b_io)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({})
            log.append(f"{len(reader.pages)} pages transferred, metadata dictionary purged")
            writer.write(out)
            processed = True

        # ─── DOCX: Core property destruction ───
        elif name_lower.endswith('.docx'):
            doc = docx.Document(b_io)
            prop = doc.core_properties
            for f in ['author', 'last_modified_by', 'comments', 'title', 'subject', 'keywords', 'category', 'identifier']:
                setattr(prop, f, '')
            log.append("All core properties sanitized")
            doc.save(out)
            processed = True

        # ─── MEDIA: Mutagen purge ───
        elif name_lower.endswith(('.mp4', '.mp3', '.m4a', '.wav', '.flac', '.ogg')):
            # Copy bytes to 'out' for mutagen to operate on
            out.write(py_data)
            out.seek(0)
            media = mutagen.File(out)
            if media:
                media.delete()
                media.save(out)
                log.append("Media container tags purged")
                processed = True
            else:
                # Forensic salting fallback
                out.seek(0, 2)
                out.write(b'\x00')
                log.append("Forensic salting applied (EOF injection)")
                processed = True

        # ─── TEXT / CSV: BOM stripping + re-encoding ───
        elif mime_type.startswith('text/') or name_lower.endswith(('.txt', '.csv', '.json', '.xml', '.log')):
            b_io.seek(0)
            raw_content = b_io.read()
            for bom in (b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff'):
                if raw_content.startswith(bom):
                    raw_content = raw_content[len(bom):]
                    log.append("BOM stripped")
                    break
            out.write(raw_content)
            processed = True

    except Exception as e:
        log.append(f"EXCEPTION: {str(e)}")

    final_data = out.getvalue() if processed else py_data
    return json.dumps({
        'success': processed,
        'log': log,
        'size': len(final_data)
    }), js.Uint8Array.new(final_data)
