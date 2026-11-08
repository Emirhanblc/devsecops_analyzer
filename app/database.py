import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Yerel çalıştırmada .env dosyasındaki DATABASE_URL / DB_HOST değerlerini okur.
load_dotenv()


def _resolve_database_url() -> str:
    """
    Veritabanı adresini ortama göre seçer.

    - DATABASE_URL verilmişse doğrudan onu kullanır.
    - Docker içinde servis adı 'db' çalışır.
    - Bilgisayarda uvicorn ile çalıştırırken Postgres localhost:5432'dedir.
    """
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url

    # Konteyner içinde /.dockerenv dosyası bulunur; yoksa yerel geliştirmedir.
    default_host = "db" if Path("/.dockerenv").exists() else "localhost"
    db_host = os.getenv("DB_HOST", default_host)
    return f"postgresql://secuser:secpass123@{db_host}:5432/secdb"


SQLALCHEMY_DATABASE_URL = _resolve_database_url()

# Veritabanı motorunu oluşturuyoruz
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Veritabanı oturumlarını oluşturacak sınıf
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Veritabanı modellerimizi (tabloları) türeteceğimiz temel sınıf
Base = declarative_base()

# Veritabanı bağlantısını açıp kapatacak yardımcı fonksiyon
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
