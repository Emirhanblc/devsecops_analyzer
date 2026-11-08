from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from .database import Base


class Vulnerability(Base):
    """Yapay zeka analizi sonucunda bulunan zafiyetleri saklayan tablo."""

    __tablename__ = "vulnerabilities"

    # Her kayıt için veritabanı tarafından üretilecek benzersiz kimlik.
    id = Column(Integer, primary_key=True, index=True)

    # Taranan depo ve zafiyetin bulunduğu dosyaya ait bilgiler.
    repo_url = Column(String, index=True)
    file_name = Column(String)

    # Zafiyetin adı, satır numarası ve önerilen çözüm.
    vulnerability_name = Column(String)
    line_number = Column(String)
    suggestion = Column(String)

    # Kayıt eklenirken tarih verilmezse o anki UTC zamanı kullanılır.
    created_at = Column(DateTime, default=datetime.utcnow)
