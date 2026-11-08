# =============================================================================
# DİKKAT: BU DOSYA KASITLI OLARAK ZAFİYETLİDİR.
#
# Bu kod üretim ortamında kullanılmak üzere yazılmamıştır.
# Yalnızca GitHub Actions CI/CD güvenlik tarama sürecinin
# (security-scan.yml / scan.py) OWASP Top 10 açıklarını
# yakalayıp yakalayamadığını doğrulamak için eklenmiştir.
#
# SQL Injection örneği bilinçli olarak hiçbir girdi doğrulaması
# veya parametreli sorgu olmadan bırakılmıştır.
# =============================================================================

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "test_vuln.db"


def init_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, email) "
        "VALUES (1, 'demo', 'demo@example.com')"
    )
    connection.commit()
    return connection


def get_user_by_username(username: str) -> list:
    """Kullanıcı kaydını ada göre döndürür."""
    connection = init_db()
    cursor = connection.cursor()

    # ZAFİYET (SQL Injection): Kullanıcı girdisi filtrelenmeden
    # f-string ile doğrudan SQL sorgusuna ekleniyor.
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    connection.close()
    return rows


if __name__ == "__main__":
    user_input = input("Kullanıcı adı: ")
    print(get_user_by_username(user_input))
