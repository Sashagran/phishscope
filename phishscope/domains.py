"""Domain utilities: registrable domain extraction and look-alike (typosquatting / homoglyph) detection."""

from __future__ import annotations

# Brands commonly impersonated in phishing, with their legitimate registrable domains.
BRANDS: dict[str, set[str]] = {
    "PayPal": {"paypal.com"},
    "Microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"},
    "Apple": {"apple.com", "icloud.com"},
    "Google": {"google.com", "gmail.com", "youtube.com"},
    "Amazon": {"amazon.com", "amazon.de", "amazon.co.uk", "amazonaws.com"},
    "Netflix": {"netflix.com"},
    "DHL": {"dhl.com", "dhl.de"},
    "Sberbank": {"sberbank.ru", "sber.ru"},
    "Gosuslugi": {"gosuslugi.ru"},
    "Yandex": {"yandex.ru", "ya.ru", "yandex.com"},
    "VK": {"vk.com", "vk.ru"},
    "Tinkoff": {"tinkoff.ru", "tbank.ru"},
    "Ozon": {"ozon.ru"},
    "Wildberries": {"wildberries.ru", "wb.ru"},
}

# Names (incl. Russian spellings) that indicate a brand in a display name.
BRAND_NAMES: dict[str, list[str]] = {
    "PayPal": ["PayPal"], "Microsoft": ["Microsoft", "Office 365", "Outlook"], "Apple": ["Apple", "iCloud"],
    "Google": ["Google", "Gmail"], "Amazon": ["Amazon"], "Netflix": ["Netflix"], "DHL": ["DHL"],
    "Sberbank": ["Sberbank", "Сбербанк", "Сбер"], "Gosuslugi": ["Gosuslugi", "Госуслуги"],
    "Yandex": ["Yandex", "Яндекс"], "VK": ["ВКонтакте", "VKontakte"], "Tinkoff": ["Tinkoff", "Тинькофф", "Т-Банк"],
    "Ozon": ["Ozon", "Озон"], "Wildberries": ["Wildberries", "Вайлдберриз"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "clck.ru", "shorturl.at",
}

# second-level public suffixes we care about (no external PSL dependency)
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "com.tr", "com.ua", "msk.ru", "spb.ru",
    "com.ru", "co.in", "github.io", "herokuapp.com", "web.app", "firebaseapp.com", "pages.dev", "netlify.app",
}

# visually confusable characters mapped to the ASCII letter they imitate
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s",
    "ɑ": "a", "ο": "o", "ν": "v", "ρ": "p",
})


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _normalize(label: str) -> str:
    s = label.translate(_HOMOGLYPHS)
    return s.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(host: str) -> str | None:
    """Return the brand a host imitates, or None.

    Catches typosquatting (paypa1.com, rnicrosoft.com), homoglyphs (pаypal.com with Cyrillic 'а'),
    and brand-in-subdomain tricks (paypal.com.secure-login.example).
    """
    if not host:
        return None
    host = _decode_idna(host.lower())
    reg = registrable_domain(host)
    legit = {d for ds in BRANDS.values() for d in ds}
    if reg in legit:
        return None

    reg_label = reg.split(".")[0]
    norm = _normalize(reg_label)

    for brand, domains in BRANDS.items():
        for d in domains:
            label = d.split(".")[0]
            if len(label) < 4:
                continue
            # homoglyph / character substitution
            if norm == label and reg_label != label:
                return brand
            # small edit distance on longer names
            if len(label) >= 6 and _levenshtein(norm, label) == 1:
                return brand
            # brand + decoration in the registrable label: paypal-secure.com, sberbank-online.ru
            if f"{label}-" in norm or f"-{label}" in norm:
                return brand
            # legit domain used as a subdomain prefix: paypal.com.account-check.net
            if host.startswith(d + ".") or f".{d}." in host:
                return brand
    return None
