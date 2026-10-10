"""
CIPHER01 — Encoded Data Decoder & Rescanner
Detects and decodes: Base64, Hex, URL-encoding, HTML entities, Unicode escapes.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings


@dataclass
class DecodedLayer:
    encoding: str
    decoded_text: str
    depth: int


@dataclass
class DecodeResult:
    original: str
    layers: list[DecodedLayer] = field(default_factory=list)
    final_text: str = ""
    encoding_detected: bool = False
    risk_contribution: float = 0.0


# Patterns for detecting encoding wrappers
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HEX_PATTERN = re.compile(r"^(?:0x)?[0-9A-Fa-f]{8,}$")
URL_ENCODED_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
HTML_ENTITY_PATTERN = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);")
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")
ROT13_WORD_PATTERN = re.compile(r"\b[a-zA-Z]{3,}\b")


def _safe_b64decode(s: str) -> Optional[str]:
    try:
        # Pad if needed
        padded = s + "=" * (-len(s) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        # Only return if it's mostly printable
        printable = sum(1 for c in decoded_str if c.isprintable() or c in "\r\n\t")
        if printable / max(len(decoded_str), 1) > 0.7:
            return decoded_str
    except Exception:
        pass
    return None


def _safe_hex_decode(s: str) -> Optional[str]:
    try:
        clean = s[2:] if s.startswith("0x") else s
        decoded_bytes = bytes.fromhex(clean)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        printable = sum(1 for c in decoded_str if c.isprintable() or c in "\r\n\t")
        if printable / max(len(decoded_str), 1) > 0.7:
            return decoded_str
    except Exception:
        pass
    return None


def _decode_unicode_escapes(s: str) -> str:
    try:
        return s.encode("utf-8").decode("unicode_escape")
    except Exception:
        return s


class EncodingDecoder:
    """
    Detects encoded payloads and decodes them layer-by-layer for rescanning.
    Hard limits prevent CPU exhaustion from deeply nested encoding.
    """

    def __init__(self):
        self.max_depth = settings.max_decode_depth
        self.max_input_size = settings.max_payload_size_mb * 1024 * 1024

    def decode(self, text: str) -> DecodeResult:
        if not text or len(text.encode()) > self.max_input_size:
            return DecodeResult(original=text, final_text=text)

        result = DecodeResult(original=text, final_text=text)
        current = text
        depth = 0

        while depth < self.max_depth:
            decoded, encoding = self._try_decode_one_layer(current)
            if decoded is None or decoded == current:
                break
            layer = DecodedLayer(
                encoding=encoding,
                decoded_text=decoded[:4096],  # cap output length
                depth=depth + 1,
            )
            result.layers.append(layer)
            result.encoding_detected = True
            current = decoded
            depth += 1

        result.final_text = current
        if result.encoding_detected:
            # Nested encoding is inherently suspicious
            result.risk_contribution = 4.0 + depth * 1.5

        return result

    def _try_decode_one_layer(self, text: str) -> tuple[Optional[str], str]:
        stripped = text.strip()

        # URL encoding
        if URL_ENCODED_PATTERN.search(stripped):
            try:
                decoded = urllib.parse.unquote(stripped)
                if decoded != stripped:
                    return decoded, "url_encoding"
            except Exception:
                pass

        # HTML entities
        if HTML_ENTITY_PATTERN.search(stripped):
            decoded = html.unescape(stripped)
            if decoded != stripped:
                return decoded, "html_entities"

        # Unicode escapes
        if UNICODE_ESCAPE_PATTERN.search(stripped):
            decoded = _decode_unicode_escapes(stripped)
            if decoded != stripped:
                return decoded, "unicode_escape"

        # Base64 — try both with and without whitespace
        no_ws = re.sub(r"\s+", "", stripped)
        if len(no_ws) >= 16 and BASE64_PATTERN.match(no_ws):
            decoded = _safe_b64decode(no_ws)
            if decoded:
                return decoded, "base64"

        # Hex
        if HEX_PATTERN.match(no_ws) and len(no_ws) >= 8:
            decoded = _safe_hex_decode(no_ws)
            if decoded:
                return decoded, "hex"

        return None, ""

    def extract_decodable_segments(self, text: str) -> list[str]:
        """Extract candidate encoded segments from larger text."""
        segments: list[str] = []

        # Base64-like segments
        for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
            seg = m.group(0)
            if _safe_b64decode(seg):
                segments.append(seg)

        # Hex segments
        for m in re.finditer(r"(?:0x)[0-9A-Fa-f]{16,}|[0-9A-Fa-f]{32,}", text):
            segments.append(m.group(0))

        return segments


encoding_decoder = EncodingDecoder()
