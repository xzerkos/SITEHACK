# SITEHACK TOOL
                                                                          

Консольный OSINT- и структурный анализатор домена: WHOIS/DNS, поиск упоминаний взломов и утечек, обход структуры сайта, классификация файлов по роли, поверхностные активные пробы (SQLi, NoSQLi, Command injection, LFI, XSS, SSTI, CSRF, open redirect, security headers, HTTP methods, rate limiting), проверка открытых артефактов (`.git/`, `.env`, backup, `/actuator`, `phpmyadmin`). Результат — отчёт в `.txt`.

Автор: **xzerkos** — [github.com/xzerkos](https://github.com/xzerkos) · tg: [@xZerkosHack](https://t.me/xZerkosHack)

---

## Требования

- Python 3.10+
- pip

## Установка

```bash
git clone <repo-url> sitehack
cd sitehack
python -m venv .venv

# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

pip install -r requirements.txt
