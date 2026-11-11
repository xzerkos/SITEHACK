import re

RULES = [
    (re.compile(r"(^|/)index\.(php|html?|js|py)$"), "front controller / точка входа"),
    (re.compile(r"(route|router|urls|routes)"), "маршрутизация запросов"),
    (re.compile(r"(controller|handler|view)"), "обработка запросов"),
    (re.compile(r"(model|entity|orm|schema)"), "модель данных / ORM"),
    (re.compile(r"(db|database|mysql|pdo|conn(ect)?)"), "работа с БД"),
    (re.compile(r"(auth|login|session|jwt)"), "аутентификация/сессии"),
    (re.compile(r"(admin|panel|dashboard)"), "админ-панель"),
    (re.compile(r"(api|rest|graphql)"), "API-слой"),
    (re.compile(r"(config|settings|\.env)"), "конфигурация/секреты"),
    (re.compile(r"(upload|file|media)"), "загрузка/работа с файлами"),
    (re.compile(r"(template|\.twig|\.blade\.php|\.jinja)"), "шаблон рендера"),
    (re.compile(r"(\.css|\.scss|\.sass|\.less)$"), "стили (static)"),
    (re.compile(r"\.(js|mjs)$"), "клиентский скрипт (static)"),
    (re.compile(r"\.(png|jpe?g|gif|svg|webp|ico)$"), "медиа (static)"),
]


def classify(path: str) -> str:
    low = path.lower()
    for rx, role in RULES:
        if rx.search(low):
            return role
    return "unclassified"


def map_roles(paths: list[str]) -> list[tuple[str, str]]:
    return [(p, classify(p)) for p in paths]