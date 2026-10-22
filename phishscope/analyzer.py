"""Static phishing analysis of RFC 5322 messages (.eml).

The analyzer never opens links or executes attachments: it only inspects headers,
bodies and attachment metadata, so it is safe to run on live samples.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .domains import BRAND_NAMES, BRANDS, URL_SHORTENERS, lookalike_of, registrable_domain

# ---------------------------------------------------------------- results


@dataclass
class Indicator:
    id: str
    category: str
    title: str
    weight: int
    details: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "category": self.category, "title": self.title, "weight": self.weight, "details": self.details}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    risky: bool
    reason: str = ""


@dataclass
class Link:
    url: str
    text: str = ""
    domain: str = ""


@dataclass
class Report:
    subject: str
    sender: str
    sender_domain: str
    score: int = 0
    verdict: str = "clean"
    indicators: list[Indicator] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth: dict = field(default_factory=dict)
    received_hops: int = 0

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "score": self.score,
            "verdict": self.verdict,
            "authentication": self.auth,
            "received_hops": self.received_hops,
            "indicators": [i.to_dict() for i in self.indicators],
            "iocs": {
                "domains": sorted({l.domain for l in self.links if l.domain}),
                "urls": [l.url for l in self.links],
                "attachment_sha256": [a.sha256 for a in self.attachments],
            },
            "attachments": [a.__dict__ for a in self.attachments],
        }


# ---------------------------------------------------------------- helpers

RISKY_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "msi",
    "lnk", "iso", "img", "vhd", "jar", "reg", "cpl", "html", "htm", "svg", "one",
    "docm", "xlsm", "pptm", "dotm", "xlam",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"within \d+ (hours?|minutes?)", r"\bact now\b",
    r"\bfinal (notice|warning)\b", r"\bsuspend(ed)?\b", r"\blocked\b", r"\bexpires? (today|soon)\b",
    r"срочно", r"немедленно", r"в течение \d+ (час|минут)", r"заблокирован", r"последнее предупреждение",
    r"приостановлен",
]
CREDENTIAL_PATTERNS = [
    r"\b(verify|confirm|update|validate) (your )?(account|password|identity|payment|details)\b",
    r"\b(log ?in|sign ?in) to (your )?account\b", r"\bpassword\b", r"\bone[- ]time (code|password)\b",
    r"подтверд\w+ (учетн|аккаунт|личност|данн|платеж)", r"\bпарол\w*", r"код из (смс|sms)", r"введите данные карты",
]
PAYMENT_PATTERNS = [
    r"\b(wire|bank) transfer\b", r"\binvoice\b", r"\bgift ?cards?\b", r"\bbitcoin|crypto(currency)?\b",
    r"\bnew (bank )?account details\b", r"оплат\w+ сч[её]т", r"смен\w+ реквизит", r"перевод\w* (средств|денег)",
]

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'\)\]]+""", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.text_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "form":
            self.forms.append(a.get("action") or "")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._text).strip()))
            self._href = None

    def handle_data(self, data):
        self.text_chunks.append(data)
        if self._href is not None:
            self._text.append(data)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _domain_of_addr(addr: str) -> str:
    _, email = parseaddr(addr)
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""


def _count_patterns(text: str, patterns: Iterable[str]) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


# ---------------------------------------------------------------- analyzer


def parse_auth_results(msg: EmailMessage) -> dict:
    """Extract SPF / DKIM / DMARC verdicts from Authentication-Results headers."""
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for header in msg.get_all("Authentication-Results", []) or []:
        for mech in results:
            m = re.search(rf"\b{mech}=(\w+)", str(header), re.IGNORECASE)
            if m and results[mech] == "none":
                results[mech] = m.group(1).lower()
    if results["spf"] == "none":
        rs = msg.get("Received-SPF")
        if rs:
            results["spf"] = str(rs).split()[0].lower()
    return results


def analyze_message(msg: EmailMessage) -> Report:
    from_header = str(msg.get("From", ""))
    display_name, from_addr = parseaddr(from_header)
    sender_domain = _domain_of_addr(from_header)
    report = Report(subject=str(msg.get("Subject", "")), sender=from_header, sender_domain=sender_domain)
    add = report.indicators.append

    # ---- authentication
    report.auth = auth = parse_auth_results(msg)
    if auth["dmarc"] in {"fail", "quarantine", "reject"}:
        add(Indicator("AUTH-DMARC", "authentication", "DMARC check failed", 30, f"dmarc={auth['dmarc']}"))
    if auth["spf"] in {"fail", "softfail"}:
        add(Indicator("AUTH-SPF", "authentication", "SPF check failed", 15 if auth["spf"] == "fail" else 8, f"spf={auth['spf']}"))
    if auth["dkim"] in {"fail", "neutral", "permerror"}:
        add(Indicator("AUTH-DKIM", "authentication", "DKIM signature invalid", 15, f"dkim={auth['dkim']}"))
    if all(v == "none" for v in auth.values()):
        add(Indicator("AUTH-NONE", "authentication", "No sender authentication results", 5,
                      "message carries no SPF/DKIM/DMARC verdicts"))

    # ---- sender identity
    reply_to = msg.get("Reply-To")
    if reply_to:
        rt_domain = _domain_of_addr(str(reply_to))
        if rt_domain and registrable_domain(rt_domain) != registrable_domain(sender_domain):
            add(Indicator("HDR-REPLYTO", "sender", "Reply-To points to a different domain", 15,
                          f"From: {sender_domain} -> Reply-To: {rt_domain}"))
    return_path = msg.get("Return-Path")
    if return_path:
        rp_domain = _domain_of_addr(str(return_path))
        if rp_domain and registrable_domain(rp_domain) != registrable_domain(sender_domain):
            add(Indicator("HDR-RETURNPATH", "sender", "Envelope sender differs from From domain", 5,
                          f"Return-Path: {rp_domain}"))

    if display_name:
        embedded = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", display_name)
        if embedded and embedded.group(0).lower() != from_addr.lower():
            add(Indicator("HDR-DISPLAYADDR", "sender", "Display name contains a different e-mail address", 20,
                          f"'{display_name}' <{from_addr}>"))
        for brand, names in BRAND_NAMES.items():
            mentioned = any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", display_name, re.IGNORECASE) for n in names)
            if mentioned and registrable_domain(sender_domain) not in BRANDS[brand]:
                add(Indicator("HDR-BRAND", "sender", f"Display name impersonates {brand}", 25,
                              f"'{display_name}' sent from {sender_domain}"))
                break

    if (brand := lookalike_of(sender_domain)):
        add(Indicator("DOM-LOOKALIKE-SENDER", "sender", f"Sender domain is a look-alike of {brand}", 30, sender_domain))

    report.received_hops = len(msg.get_all("Received", []) or [])

    # ---- bodies
    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            content = part.get_payload(decode=True).decode("utf-8", "replace") if part.get_payload(decode=True) else ""
        if ctype == "text/plain":
            plain_parts.append(content)
        elif ctype == "text/html":
            html_parts.append(content)

    extractor = _LinkExtractor()
    for h in html_parts:
        extractor.feed(h)
    text = "\n".join(plain_parts + extractor.text_chunks)

    seen: set[str] = set()
    for href, anchor in extractor.links:
        if href.lower().startswith(("http://", "https://")) and href not in seen:
            seen.add(href)
            report.links.append(Link(href, anchor, _host(href)))
    for url in URL_RE.findall("\n".join(plain_parts)):
        url = url.rstrip(".,;")
        if url not in seen:
            seen.add(url)
            report.links.append(Link(url, "", _host(url)))

    _analyze_links(report, sender_domain)

    if extractor.forms:
        add(Indicator("BODY-FORM", "content", "HTML form embedded in the e-mail", 20,
                      "forms in e-mail bodies are used to harvest credentials"))

    urgency = _count_patterns(text, URGENCY_PATTERNS)
    if urgency:
        add(Indicator("TXT-URGENCY", "content", "Urgency / pressure language", min(5 * len(urgency), 15), ", ".join(urgency)))
    creds = _count_patterns(text, CREDENTIAL_PATTERNS)
    if creds:
        add(Indicator("TXT-CREDS", "content", "Requests credentials or verification", min(7 * len(creds), 20), ", ".join(creds)))
    pay = _count_patterns(text, PAYMENT_PATTERNS)
    if pay:
        add(Indicator("TXT-PAYMENT", "content", "Payment / bank details request", min(7 * len(pay), 20), ", ".join(pay)))

    # ---- attachments
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        name = part.get_filename() or "(unnamed)"
        exts = [e.lower() for e in name.split(".")[1:]]
        risky, reason = False, ""
        if exts and exts[-1] in RISKY_EXTENSIONS:
            risky, reason = True, f"executable/active content (.{exts[-1]})"
        if len(exts) >= 2 and exts[-1] in RISKY_EXTENSIONS | ARCHIVE_EXTENSIONS and exts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            risky, reason = True, f"double extension (.{exts[-2]}.{exts[-1]})"
        if "‮" in name:
            risky, reason = True, "right-to-left override character in filename"
        if exts and exts[-1] in ARCHIVE_EXTENSIONS and not risky:
            reason = "archive (contents not inspected)"
        att = Attachment(name, part.get_content_type(), len(payload), hashlib.sha256(payload).hexdigest(), risky, reason)
        report.attachments.append(att)
        if risky:
            add(Indicator("ATT-RISKY", "attachment", "Dangerous attachment type", 35, f"{name}: {reason}"))
        elif exts and exts[-1] in ARCHIVE_EXTENSIONS:
            add(Indicator("ATT-ARCHIVE", "attachment", "Archive attachment", 10, name))

    # ---- verdict
    report.score = min(100, sum(i.weight for i in report.indicators))
    report.verdict = (
        "malicious" if report.score >= 70 else
        "suspicious" if report.score >= 40 else
        "caution" if report.score >= 15 else
        "clean"
    )
    report.indicators.sort(key=lambda i: -i.weight)
    return report


def _analyze_links(report: Report, sender_domain: str) -> None:
    add = report.indicators.append
    flagged: set[str] = set()

    def once(key: str, ind: Indicator) -> None:
        if key not in flagged:
            flagged.add(key)
            add(ind)

    for link in report.links:
        host = link.domain
        if not host:
            continue
        if _is_ip(host):
            once("ip:" + host, Indicator("URL-IP", "links", "Link points to a raw IP address", 25, link.url))
        if host.startswith("xn--") or ".xn--" in host:
            once("puny:" + host, Indicator("URL-PUNYCODE", "links", "Internationalized (punycode) domain", 20, host))
        if registrable_domain(host) in URL_SHORTENERS:
            once("short:" + host, Indicator("URL-SHORTENER", "links", "URL shortener hides the destination", 10, link.url))
        if "@" in (urlsplit(link.url).netloc or ""):
            once("at:" + link.url, Indicator("URL-USERINFO", "links", "Credentials-style '@' trick in URL", 25, link.url))
        if (brand := lookalike_of(host)):
            once("look:" + host, Indicator("DOM-LOOKALIKE-URL", "links", f"Link to a look-alike of {brand}", 35, host))
        if link.url.lower().startswith("http://") and any(w in link.url.lower() for w in ("login", "signin", "verify", "account")):
            once("http:" + host, Indicator("URL-HTTP-LOGIN", "links", "Login page over plain HTTP", 10, link.url))

        # anchor text shows one domain, href goes elsewhere
        shown = URL_RE.search(link.text) or re.search(r"\b(?:www\.)?[\w-]+(?:\.[\w-]+)+\b", link.text or "")
        if shown:
            shown_host = _host(shown.group(0)) if shown.group(0).lower().startswith("http") else shown.group(0).lower()
            shown_host = shown_host.removeprefix("www.")
            if "." in shown_host and registrable_domain(shown_host) != registrable_domain(host):
                once("mismatch:" + host, Indicator("URL-MISMATCH", "links", "Link text does not match its destination", 30,
                                                   f"shows '{shown_host}' but goes to '{host}'"))


def analyze_bytes(raw: bytes) -> Report:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return analyze_message(msg)  # type: ignore[arg-type]


def analyze_file(path: str | Path) -> Report:
    return analyze_bytes(Path(path).read_bytes())
