"""
Metadata extraction from an uploaded file.
  * Images -> EXIF incl. GPS (Pillow)
  * PDFs   -> document properties (pypdf)
  * Any    -> basic file facts (size, sha256)
"""
import hashlib
import io

try:
    from PIL import Image, ExifTags
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

try:
    from pypdf import PdfReader
    _HAS_PDF = True
except Exception:
    _HAS_PDF = False

_GPS_TAG = 34853


def _to_deg(value):
    try:
        d, m, s = value
        return float(d) + float(m) / 60 + float(s) / 3600
    except Exception:
        return None


def _exif(raw: bytes) -> dict:
    out = {"exif": {}, "gps": None}
    if not _HAS_PIL:
        out["error"] = "Pillow not installed"
        return out
    try:
        img = Image.open(io.BytesIO(raw))
        out["dimensions"] = f"{img.width}x{img.height}"
        out["format"] = img.format
        exif = img._getexif() or {}
        readable = {}
        for tag_id, val in exif.items():
            tag = ExifTags.TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in val.items()}
                lat = _to_deg(gps.get("GPSLatitude"))
                lon = _to_deg(gps.get("GPSLongitude"))
                if lat is not None and lon is not None:
                    if gps.get("GPSLatitudeRef") == "S":
                        lat = -lat
                    if gps.get("GPSLongitudeRef") == "W":
                        lon = -lon
                    out["gps"] = {"lat": round(lat, 6), "lon": round(lon, 6)}
                continue
            if isinstance(val, bytes):
                val = val.decode(errors="replace")
            readable[str(tag)] = str(val)[:200]
        out["exif"] = readable
    except Exception as e:
        out["error"] = f"{type(e).__name__}: not a readable image"
    return out


def _pdf(raw: bytes) -> dict:
    if not _HAS_PDF:
        return {"error": "pypdf not installed"}
    try:
        reader = PdfReader(io.BytesIO(raw))
        info = reader.metadata or {}
        meta = {str(k).lstrip("/"): str(v) for k, v in info.items()}
        meta["pages"] = str(len(reader.pages))
        return {"document": meta}
    except Exception as e:
        return {"error": f"{type(e).__name__}: not a readable PDF"}


def extract(filename: str, raw: bytes) -> dict:
    name = (filename or "file").lower()
    result = {
        "filename": filename,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "md5": hashlib.md5(raw).hexdigest(),
        "type": "metadata",
    }
    if name.endswith((".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic", ".webp")):
        result["kind"] = "image"
        result.update(_exif(raw))
    elif name.endswith(".pdf"):
        result["kind"] = "pdf"
        result.update(_pdf(raw))
    else:
        result["kind"] = "binary"
        result["note"] = "No EXIF/PDF extractor for this type — hash + size only."
    return result
