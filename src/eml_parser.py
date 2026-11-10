"""
Módulo Forense de Parsing de Archivos .eml (MIME) — Fase 1 del Analizador de Phishing.

Extrae de forma segura (sin ejecutar adjuntos ni abrir enlaces):
1. Cabeceras de identidad: From, Return-Path, Reply-To, To, Subject, Message-ID.
2. Cabeceras de autenticación e infraestructura: Received (IP origen), SPF, DKIM y DMARC.
3. Hipervínculos HTML (<a href="...">texto</a>) detectando engaños visuales (Link Mismatch).
4. Archivos adjuntos: nombre, tamaño, doble extensión (.pdf.exe), Magic Bytes ('MZ') y Hash SHA-256.
"""

from dataclasses import dataclass, field
import email
from email import policy
from email.utils import parseaddr
import hashlib
from pathlib import Path
import re
from typing import List
from urllib.parse import urlparse


@dataclass
class EmailLink:
    """Representa un hipervínculo extraído del cuerpo HTML del correo."""

    href_url: str
    visible_text: str
    href_domain: str
    is_deceptive_mismatch: bool  # True si el texto visible finge ser otro dominio distinto al href


@dataclass
class EmailAttachment:
    """Representa un archivo adjunto extraído del correo junto con sus indicadores forenses."""

    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    has_double_extension: bool
    is_windows_pe_executable: bool


@dataclass
class ParsedEmail:
    """Estructura completa de un correo .eml normalizado para triaje SOC L1."""

    filepath: str
    subject: str
    from_header: str
    from_address: str
    from_domain: str
    return_path_address: str
    return_path_domain: str
    reply_to_address: str
    reply_to_domain: str
    to_address: str
    date: str
    message_id: str
    sender_ip: str
    spf_result: str
    dkim_result: str
    dmarc_result: str
    body_text: str
    links: List[EmailLink] = field(default_factory=list)
    attachments: List[EmailAttachment] = field(default_factory=list)


ANCHOR_REGEX = re.compile(
    r'<a\s+[^>]*href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<text>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
RECEIVED_IP_REGEX = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
DOUBLE_EXT_REGEX = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|vbs|js|ps1|com)$",
    re.IGNORECASE,
)


def _extract_domain(email_addr: str) -> str:
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip()
    return ""


def _extract_auth_metric(auth_results: str, metric: str) -> str:
    match = re.search(rf"\b{metric}=([a-zA-Z0-9_]+)", auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def _extract_links_from_html(html_content: str) -> List[EmailLink]:
    links: List[EmailLink] = []
    for match in ANCHOR_REGEX.finditer(html_content):
        href = match.group("href").strip()
        text = re.sub(r"<[^>]+>", "", match.group("text")).strip()
        href_domain = (urlparse(href).hostname or "").lower()

        is_mismatch = False
        if text.lower().startswith(("http://", "https://", "www.")):
            visible_domain = (urlparse(text).hostname or "").lower()
            if visible_domain and href_domain and visible_domain != href_domain:
                is_mismatch = True

        links.append(
            EmailLink(
                href_url=href,
                visible_text=text,
                href_domain=href_domain,
                is_deceptive_mismatch=is_mismatch,
            )
        )
    return links


def parse_eml_file(filepath: str | Path) -> ParsedEmail:
    """Abre y analiza un archivo .eml extrayendo cabeceras, enlaces y hashes de adjuntos."""
    path = Path(filepath)
    raw_bytes = path.read_bytes()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    from_header = str(msg.get("From", ""))
    _, from_addr = parseaddr(from_header)
    _, return_path_addr = parseaddr(str(msg.get("Return-Path", "")))
    _, reply_to_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, to_addr = parseaddr(str(msg.get("To", "")))

    received_header = str(msg.get("Received", ""))
    ip_match = RECEIVED_IP_REGEX.search(received_header)
    sender_ip = ip_match.group(1) if ip_match else "Unknown"

    auth_results = str(msg.get("Authentication-Results", ""))
    spf_res = _extract_auth_metric(auth_results, "spf")
    dkim_res = _extract_auth_metric(auth_results, "dkim")
    dmarc_res = _extract_auth_metric(auth_results, "dmarc")

    body_chunks: List[str] = []
    links: List[EmailLink] = []
    attachments: List[EmailAttachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()

        if filename or content_disposition == "attachment":
            fname = filename or "unnamed_attachment.bin"
            payload_bytes = part.get_payload(decode=True) or b""
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
            has_double_ext = bool(DOUBLE_EXT_REGEX.search(fname))
            is_pe = payload_bytes.startswith(b"MZ")

            attachments.append(
                EmailAttachment(
                    filename=fname,
                    content_type=part.get_content_type(),
                    size_bytes=len(payload_bytes),
                    sha256=sha256_hash,
                    has_double_extension=has_double_ext,
                    is_windows_pe_executable=is_pe,
                )
            )
        else:
            ctype = part.get_content_type()
            payload_bytes = part.get_payload(decode=True) or b""
            text_content = payload_bytes.decode("utf-8", errors="replace")
            body_chunks.append(text_content)
            if ctype == "text/html":
                links.extend(_extract_links_from_html(text_content))

    return ParsedEmail(
        filepath=str(path),
        subject=str(msg.get("Subject", "")),
        from_header=from_header,
        from_address=from_addr.lower(),
        from_domain=_extract_domain(from_addr),
        return_path_address=return_path_addr.lower(),
        return_path_domain=_extract_domain(return_path_addr),
        reply_to_address=reply_to_addr.lower(),
        reply_to_domain=_extract_domain(reply_to_addr),
        to_address=to_addr.lower(),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        sender_ip=sender_ip,
        spf_result=spf_res,
        dkim_result=dkim_res,
        dmarc_result=dmarc_res,
        body_text="\n".join(body_chunks),
        links=links,
        attachments=attachments,
    )
