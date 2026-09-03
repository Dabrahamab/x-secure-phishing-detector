from __future__ import annotations

import json
import os
import re
import smtplib
import time
from email.message import EmailMessage
from types import SimpleNamespace

from flask import Flask, jsonify, render_template, request

from phishing_system import PhishingTakedownSystem

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

system = PhishingTakedownSystem()


def _load_smtp_config() -> dict:
    config = {
        "smtp_server": os.environ.get("SMTP_SERVER", ""),
        "smtp_port": int(os.environ.get("SMTP_PORT", "587")),
        "username": os.environ.get("SMTP_USERNAME", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_email": os.environ.get("FROM_EMAIL", ""),
    }
    # Credentials are intentionally NOT hardcoded here. They come from the
    # environment or from a local, git-ignored smtp_config.json file so secrets
    # are never committed to the repository.
    local_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smtp_config.json")
    if os.path.exists(local_file):
        try:
            with open(local_file, "r", encoding="utf-8") as handle:
                stored = json.load(handle)
            for key in ("smtp_server", "smtp_port", "username", "password", "from_email"):
                if not config.get(key) and stored.get(key):
                    config[key] = stored[key]
            if config.get("smtp_port"):
                config["smtp_port"] = int(config["smtp_port"])
        except Exception:
            pass
    if not config.get("smtp_server"):
        config["smtp_server"] = "smtp.gmail.com"
    if not config.get("from_email") and config.get("username"):
        config["from_email"] = config["username"]
    return config


SMTP_CONFIG = _load_smtp_config()


def _normalize_urls(raw_text: str) -> list[str]:
    urls = []
    for line in raw_text.splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            urls.append(candidate)
    return urls


def _is_valid_email(email: str) -> bool:
    return _email_error(email) is None


VALID_EMAIL_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "io", "ai",
    "app", "dev", "tech", "xyz", "top", "club", "online", "site", "store",
    "shop", "live", "news", "blog", "design", "media", "social", "network",
    "digital", "solutions", "services", "cloud", "finance", "company", "agency",
    "business", "email", "group", "marketing", "money", "one", "page", "pro",
    "space", "systems", "web", "website", "work", "world", "zone", "tv",
    "me", "us", "uk", "ca", "au", "de", "fr", "es", "it", "nl", "be", "ch",
    "at", "se", "no", "fi", "dk", "is", "ie", "lu", "pt", "gr", "cy", "mt",
    "pl", "cz", "hu", "ro", "bg", "hr", "rs", "sk", "si", "lt", "lv", "ee",
    "by", "ua", "kz", "uz", "ru", "in", "jp", "cn", "kr", "hk", "tw", "sg",
    "my", "th", "ph", "id", "vn", "br", "mx", "ar", "cl", "pe", "co", "ve",
    "ec", "uy", "py", "bo", "za", "ng", "gh", "ke", "eg", "ma", "dz", "tn",
    "sa", "ae", "qa", "kw", "bh", "om", "il", "tr", "pk", "bd", "lk", "np",
    "nz", "mn", "az", "ge", "am", "md", "mk", "al", "ba",
    "academy", "accountants", "adult", "apartments", "associates", "bike",
    "boutique", "builders", "camera", "camp", "capital", "care", "careers",
    "casino", "catering", "center", "ceo", "city", "claims", "cleaning",
    "clinic", "clothing", "coach", "codes", "coffee", "college", "community",
    "computer", "condos", "construction", "consulting", "contractors",
    "cooking", "cool", "coop", "coupons", "credit", "creditcard", "cruises",
    "dance", "dating", "delivery", "dental", "diamonds", "directory",
    "discount", "doctor", "dog", "domains", "education", "energy",
    "engineering", "enterprises", "equipment", "estate", "events", "exchange",
    "expert", "exposed", "fail", "farm", "fashion", "fitness", "flights",
    "florist", "flowers", "football", "foundation", "fun", "fund", "furniture",
    "gallery", "games", "garden", "gift", "gifts", "glass", "global", "golf",
    "gratis", "gripe", "guitars", "guru", "health", "healthcare", "help",
    "hiphop", "hockey", "holdings", "holiday", "hospital", "host", "house",
    "immobilien", "industries", "institute", "insure", "international",
    "investments", "jetzt", "jewelry", "juegos", "kaufen", "kim", "kitchen",
    "land", "lawyer", "lease", "legal", "life", "lighting", "limited",
    "limo", "link", "loan", "loans", "lol", "maison", "market", "mba",
    "medical", "memorial", "menu", "mobi", "moda", "mortgage", "movie",
    "museum", "name", "navy", "ninja", "partners", "parts", "photography",
    "photos", "pics", "pictures", "pink", "pizza", "place", "plumbing",
    "plus", "poker", "press", "productions", "properties", "protection",
    "pub", "recipes", "rehab", "reise", "reisen", "rent", "rentals",
    "repair", "report", "reviews", "rich", "rocks", "rodeo", "run", "salon",
    "school", "schule", "science", "security", "sexy", "shoes", "shopping",
    "show", "singles", "soccer", "solar", "studio", "style", "supplies",
    "supply", "support", "surgery", "tattoo", "tax", "taxi", "team",
    "technology", "tennis", "theater", "tickets", "tips", "tires", "today",
    "tools", "tours", "town", "toys", "trade", "training", "travel",
    "university", "vacations", "vegas", "ventures", "vet", "viajes",
    "video", "villas", "vision", "voyage", "watch", "weather", "wedding",
    "wiki", "wine", "winners", "works", "wtf",
}

# Disposable/temporary email addresses (e.g., yopmail, mailinator) are blocked
# so takedown requests can be traced back to a genuine contact.
DISPOSABLE_EMAIL_DOMAINS = {
    "yopmail.com", "yopmail.fr", "yopmail.net", "yopmail.co", "yopmail.org",
    "yopmail.co.in", "yopmail.io", "yopmail.info",
    "mailinator.com", "mailinator.net", "mailinator.org", "mailinator.io",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamail.de", "grr.la", "sharklasers.com",
    "tempmail.com", "temp-mail.org", "temp-mail.io", "tempmail.net",
    "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "maildrop.cc", "trashmail.com", "trashmail.net", "trashmail.org",
    "trashmail.de", "trashmail.me", "trashmail.ws", "throwawaymail.com",
    "throwawaymail.org", "throwaway.email", "throwaway.de", "mozmail.com",
    "dispostable.com", "mailnesia.com", "getnada.com", "nada.email",
    "inboxkitten.com", "emailondeck.com", "fakeinbox.com", "mailcatch.com",
    "spamgourmet.com", "spam4.me", "mail.tm", "tmpmail.org", "tmail.ws",
    "okeymail.com", "dropmail.me", "emltmp.com", "mintemail.com",
    "mailmetrash.com", "meltmail.com", "spam.la", "emailtemporario.com.br",
    "mailhour.com", "mailmoat.com", "mailnull.com", "mailexpire.com",
    "mytemp.email", "nwytg.net", "spamcero.com", "sneakemail.com",
    "spamex.com", "spamfree24.org", "tempinbox.com", "tempinbox.co.uk",
    "tempmailaddress.com", "throwawayemailaddress.com", "tmailor.com",
    "tmail9.com", "tradermail.info", "tyldd.com", "ubermail.me",
    "veryrealemail.com", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "whyyyy.me", "willselfdestruct.com", "yuurok.com", "zehnminuten.de",
    "zehnminutenmail.de", "24hourmail.com", "dodgit.com", "dodgit.org",
    "e4ward.com", "getairmail.com", "hidzz.com", "mailforspam.com",
    "mvrht.net", "spambob.com", "bobmail.info", "burnermail.io",
    "discard.email", "emailfake.com", "fakemailgenerator.com", "mytrashmail.com",
    "sendspamhere.com",
}

# Disposable/temporary email addresses (e.g., yopmail) are ALLOWED during
# testing. Set to True to reject them in production. Typos and invalid
# addresses are always rejected regardless of this flag.
BLOCK_DISPOSABLE_EMAILS = False


def _levenshtein(a: str, b: str) -> int:
    """Edit distance (insertions/deletions/substitutions) between two strings."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


DISPOSABLE_BASES = [
    "yopmail", "mailinator", "maildrop", "trashmail", "guerrillamail",
    "tempmail", "10minutemail", "throwawaymail", "fakeinbox", "getnada",
    "emailondeck", "dispostable", "mailnesia", "mintemail", "spamgourmet",
    "wegwerfmail", "temporarymail", "guerrilla", "mailcatch", "burnermail",
]


def _is_disposable_typo(domain: str) -> bool:
    """Return True if the domain's base name is close to (but not exactly)
    a known disposable-email brand. This catches typos like 'yopmail',
    'yopmaail' or 'yopmil' that would otherwise slip through."""
    base = domain.split(".")[0].strip().lower()
    tokens = re.split(r"[^a-z0-9]", base)
    base = "".join(tokens)
    if base in DISPOSABLE_BASES:
        return False
    for known in DISPOSABLE_BASES:
        if _levenshtein(base, known) <= 2 and abs(len(base) - len(known)) <= 2:
            return True
    return False


def _email_error(email: str) -> str | None:
    match = re.match(r"^[^\s@]+@([^\s@]+\.[^\s@]+)$", email or "")
    if not match:
        return "The email must be a valid email address (e.g., you@example.com)."
    domain = match.group(1).lower()
    tld = domain.rsplit(".", 1)[-1]
    if tld not in VALID_EMAIL_TLDS:
        return (f"The email domain must end in a legitimate top-level domain "
                f"(e.g., .com, .org, .net). '.{tld}' is not recognized.")
    # Always catch typos/misspellings of common temporary-email domains so the
    # address is correct even while disposable domains are allowed for testing.
    if _is_disposable_typo(domain):
        return ("That email address does not look valid - the domain "
                "appears to be misspelled (e.g. did you mean yopmail.com?).")
    if BLOCK_DISPOSABLE_EMAILS:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in DISPOSABLE_EMAIL_DOMAINS:
                return ("Disposable/temporary email addresses (e.g., yopmail, "
                        "mailinator) are not accepted.")
    return None


def _ip_display(site) -> str:
    ip_addresses = list(getattr(site, "ip_addresses", []) or [])
    if ip_addresses:
        return ip_addresses[0]
    if getattr(site, "ip_address", "Unknown") != "Unknown":
        return site.ip_address
    return "Unknown (domain does not resolve)"


def _classify_score(score: float) -> str:
    if score > 0.6:
        return "Phishing"
    if score > 0.35:
        return "Suspicious"
    return "Safe"


def _detect_fraud_type(url: str, score: float, technical_intel: dict | None = None) -> str:
    normalized = url.lower()
    if "ponzi" in normalized or "pyramid" in normalized or "scam" in normalized:
        return "Ponzi Scheme"

    if technical_intel:
        url_intel = technical_intel.get("url", {}) or {}
        clone_of = url_intel.get("clone_of")
        if clone_of:
            return f"Clone of {clone_of}"

        if url_intel.get("media_piracy_keywords"):
            return "Pirated Media Distribution / Malware Vector"

        html_intel = technical_intel.get("html", {}) or {}
        if html_intel.get("financial_red_flags"):
            return "Ponzi / Investment Scam"

    if score > 0.8:
        return "High-Risk Phishing"
    if score > 0.6:
        return "Phishing"
    if score > 0.35:
        return "Suspicious"
    return "Safe"


def _result_payload(site) -> dict:
    score = float(site.similarity_score)
    clamped_score = min(max(score, 0.0), 1.0)
    status = _classify_score(clamped_score)
    suspicious_pct = round(clamped_score * 100, 1)
    safe_pct = round((1.0 - clamped_score) * 100, 1)
    technical_intel = getattr(site, "technical_intel", {
        "domain": {},
        "network": {},
        "ssl": {},
        "url": {},
        "http": {},
        "html": {},
    })
    return {
        "url": site.url,
        "domain": site.domain,
        "ip_address": _ip_display(site),
        "ip_addresses": list(getattr(site, "ip_addresses", []) or []),
        "target_brand": getattr(site, "target_brand", "Heuristic Analysis"),
        "similarity_score": round(clamped_score, 2),
        "hosting_provider": getattr(site, "hosting_provider", "Cloud Host"),
        "registrar": getattr(site, "registrar", "Unknown"),
        "creation_date": getattr(site, "creation_date", "Unknown"),
        "expiration_date": getattr(site, "expiration_date", "Unknown"),
        "nameservers": list(getattr(site, "nameservers", [])),
        "abuse_contacts": list(getattr(site, "abuse_contacts", [])),
        "status": status,
        "fraud_type": _detect_fraud_type(site.url, clamped_score, technical_intel),
        "maliciousness": "High" if clamped_score > 0.6 else "Medium" if clamped_score > 0.35 else "Low",
        "suspicious_percentage": suspicious_pct,
        "safe_percentage": safe_pct,
        "technical_intel": technical_intel,
    }


def _send_requester_notification(requester_email: str, target_urls: list[dict], takedown_logs: list[dict] | None = None, detailed_reports: list[str] | None = None) -> bool:
    message = EmailMessage()
    message["Subject"] = "Abuse Report: Suspected phishing - takedown request submitted"
    message["From"] = SMTP_CONFIG["from_email"]
    message["To"] = requester_email
    if SMTP_CONFIG["from_email"].lower() != requester_email.lower():
        message["Bcc"] = SMTP_CONFIG["from_email"]

    body_lines = [
        "Your takedown request has been submitted to the host providers.",
        "They will review the reported URLs and follow up as appropriate.",
        "",
    ]

    if detailed_reports:
        for report in detailed_reports:
            body_lines.append(report)
            body_lines.append("")
            body_lines.append("=" * 56)
            body_lines.append("")
    else:
        body_lines.append("Reported URLs:")
        for item in target_urls:
            if item.get("status") == "Safe":
                body_lines.append(
                    f"- {item['url']} (Safe, {item['safe_percentage']}% clean)")
            else:
                body_lines.append(
                    f"- {item['url']} ({item['fraud_type']}, {item.get('status', 'Suspicious')} - risk {item['suspicious_percentage']}%)")

    if takedown_logs:
        body_lines.append("")
        body_lines.append("Providers notified:")
        for log in takedown_logs:
            notified = log.get("providers_notified") or []
            targeted = log.get("providers_targeted") or []
            if notified:
                body_lines.append(f"- {log['domain']} -> {', '.join(notified)}")
            elif targeted:
                body_lines.append(f"- {log['domain']} -> attempted {', '.join(targeted)} (failed: {log.get('error') or 'unknown'})")
            else:
                body_lines.append(f"- {log['domain']} -> no provider contact resolved")

    body_lines.append("")
    body_lines.append("Thank you for reporting this content.")
    message.set_content("\n".join(body_lines))

    try:
        with smtplib.SMTP(SMTP_CONFIG["smtp_server"], SMTP_CONFIG["smtp_port"], timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
            smtp.send_message(message)
        return True
    except Exception:
        return False


TAKEDOWN_LOG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "takedown_log.json")


def _append_takedown_log(requester_email: str, results: list[dict],
                         takedown_logs: list[dict], success_count: int) -> None:
    """Persist every submitted takedown request to a local JSON log so the
    project owner can review them later. The log file is git-ignored."""
    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "requester_email": requester_email,
        "urls": [
            {
                "url": item.get("url"),
                "domain": item.get("domain"),
                "status": item.get("status"),
                "fraud_type": item.get("fraud_type"),
                "risk_score": item.get("suspicious_percentage"),
            }
            for item in results
            if item.get("status") in ("Phishing", "Suspicious")
        ],
        "delivered": success_count,
        "outcomes": takedown_logs,
    }
    try:
        entries = []
        if os.path.exists(TAKEDOWN_LOG):
            with open(TAKEDOWN_LOG, "r", encoding="utf-8") as handle:
                entries = json.load(handle)
        if not isinstance(entries, list):
            entries = []
        entries.append(record)
        with open(TAKEDOWN_LOG, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2)
    except Exception:
        pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_urls():
    urls = _normalize_urls(request.form.get("urls", ""))

    uploaded_file = request.files.get("urls_file")
    if uploaded_file and uploaded_file.filename:
        text = uploaded_file.read().decode("utf-8", errors="ignore")
        urls.extend(_normalize_urls(text))

    if not urls:
        return jsonify({"error": "Please enter at least one URL to analyze."}), 400

    metrics = system.load_model_metrics()
    results = []
    for url in urls:
        site = system.analyze_url(url)
        results.append(_result_payload(site))

    summary = {
        "total_analyzed": len(results),
        "phishing_count": sum(1 for item in results if item["status"] == "Phishing"),
        "suspicious_count": sum(1 for item in results if item["status"] == "Suspicious"),
        "safe_count": sum(1 for item in results if item["status"] == "Safe"),
        "takedowns_sent": 0,
        "success_rate": 0,
        "model_metrics": metrics,
    }

    return jsonify({"summary": summary, "results": results})


@app.route("/api/model/evaluation", methods=["GET"])
def model_evaluation():
    return jsonify(system.load_model_metrics())


@app.route("/api/takedown", methods=["POST"])
def send_takedown():
    payload = request.get_json(silent=True) or {}
    results = payload.get("results", [])
    requester_email = (payload.get("requester_email") or "").strip()

    if not results:
        return jsonify({"error": "No analysis results to process."}), 400

    if not requester_email:
        return jsonify({"error": "The email address is required. Please enter a valid email address (e.g., you@example.com)."}), 400

    email_error = _email_error(requester_email)
    if email_error:
        return jsonify({"error": email_error}), 400

    missing_fields = [field for field in ["smtp_server", "smtp_port",
                                          "username", "password", "from_email"] if not SMTP_CONFIG.get(field)]
    if missing_fields:
        return jsonify({"error": "SMTP server settings are not configured on the backend."}), 500

    success_count = 0
    takedown_logs = []
    detailed_reports = []
    reportable = ("Phishing", "Suspicious")
    for item in results:
        if item.get("status") not in reportable:
            continue

        site = SimpleNamespace(
            url=item.get("url"),
            domain=item.get("domain"),
            ip_address=item.get("ip_address", "Unknown"),
            target_brand=item.get("target_brand", "Heuristic Analysis"),
            similarity_score=item.get("similarity_score", 0),
            hosting_provider=item.get("hosting_provider", "Cloud Host"),
            registrar=item.get("registrar", "Unknown"),
            creation_date=item.get("creation_date", "Unknown"),
            expiration_date=item.get("expiration_date", "Unknown"),
            nameservers=item.get("nameservers", []),
            abuse_contacts=item.get("abuse_contacts", []),
            country=item.get("country", "Unknown"),
            status=item.get("status", "Phishing"),
            technical_intel=item.get("technical_intel", {}),
        )

        outcome = system.send_takedown_request(site, SMTP_CONFIG)
        system.save_to_database(site, "in-memory takedown report")
        detailed_reports.append(system._build_takedown_report(site))

        takedown_logs.append({
            "domain": site.domain,
            "providers_notified": outcome.get("delivered", []),
            "providers_targeted": outcome.get("recipients", []),
            "sent": outcome.get("sent", False),
            "error": outcome.get("error"),
        })
        if outcome.get("sent"):
            success_count += 1

    reportable_present = any(item.get("status") in reportable for item in results)
    email_sent = False
    if reportable_present:
        requester_urls = [
            item for item in results if item.get("status") in reportable]
        email_sent = _send_requester_notification(
            requester_email, requester_urls, takedown_logs, detailed_reports)

    if success_count == 0 and reportable_present:
        targeted = [log.get("providers_targeted") for log in takedown_logs]
        if any(not t for t in targeted):
            message = ("Suspicious/phishing URL detected, but no abuse contact could "
                       "be resolved for the domain (the domain may be unregistered or "
                       "have no mail server). No takedown email was sent.")
        else:
            message = ("No takedown request could be delivered. "
                       "Check that the SMTP settings on the server are correct.")
    elif success_count == 0:
        message = ("No takedown request was sent because none of the analyzed "
                   "URLs were classified as Phishing or Suspicious.")
    else:
        message = f"Sent {success_count} takedown request(s) to the hosting providers."

    _append_takedown_log(requester_email, results, takedown_logs, success_count)

    return jsonify({
        "success_count": success_count,
        "email_sent": email_sent,
        "takedowns": takedown_logs,
        "message": message,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
