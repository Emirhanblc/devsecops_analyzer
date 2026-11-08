import asyncio
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse

from . import models
from .database import engine, get_db
from .services.analyzer import analyze_code_chunk_async
from .services.github import download_repo
from .services.parser import chunk_code, get_code_files_from_repo

# Modellerde tanımlanan veritabanı tablolarını, henüz yoklarsa oluşturuyoruz.
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="LLM DevSecOps Analizörü")

# HTML şablonlarının bulunduğu klasörü FastAPI'ye tanıtıyoruz.
templates = Jinja2Templates(directory="app/templates")

# Kullanıcıdan gelecek verinin yapısını Pydantic ile tanımlıyoruz
class RepoRequest(BaseModel):
    github_url: str

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    """Dashboard ana sayfasını kullanıcıya gösterir."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request},
    )

@app.get("/db-test")
def test_db_connection(db: Session = Depends(get_db)):
    return {"mesaj": "Veritabanı bağlantısı başarılı!"}


@app.get("/api/history")
def get_history(db: Session = Depends(get_db)):
    """
    Veritabanına kaydedilmiş tüm zafiyet kayıtlarını
    en yeniden eskiye doğru sıralı şekilde JSON olarak döndürür.
    """
    # PostgreSQL'deki vulnerabilities tablosunu created_at alanına göre
    # tersten (desc) sıralayarak bütün geçmiş taramaları çekiyoruz.
    records = (
        db.query(models.Vulnerability)
        .order_by(models.Vulnerability.created_at.desc())
        .all()
    )

    # SQLAlchemy nesneleri doğrudan JSON olamaz; her kaydı sözlüğe çeviriyoruz.
    return [
        {
            "id": record.id,
            "repo_url": record.repo_url,
            "file_name": record.file_name,
            "vulnerability_name": record.vulnerability_name,
            "line_number": record.line_number,
            "suggestion": record.suggestion,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
        for record in records
    ]

# YENİ ROTAMIZ: Repo indirme işlemi
@app.post("/fetch-repo")
def fetch_repository(request: RepoRequest):
    """
    Kullanıcıdan alınan GitHub URL'sini indirir ve dizine çıkartır.
    """
    try:
        # İndirme fonksiyonunu çağırıyoruz
        extracted_folder_path = download_repo(request.github_url)
        
        return {
            "durum": "başarılı",
            "mesaj": "Repo başarıyla indirildi ve çıkartıldı.",
            "dizin": extracted_folder_path
        }
    except ValueError as ve:
        # URL hatalıysa 400 Bad Request döneriz
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        # Diğer hatalar için 500 Internal Server Error döneriz
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze-repo")
async def analyze_repository(
    request: RepoRequest,
    db: Session = Depends(get_db),
):
    """
    GitHub reposunu indirir, desteklenen kod dosyalarını tarar ve bulunan
    kritik/yüksek seviyeli zafiyetleri Dashboard'ın beklediği yapıda döndürür.
    """
    try:
        # requests tabanlı indirme işlemi bloklayıcı olduğu için ayrı iş
        # parçacığında çalıştırarak FastAPI olay döngüsünü meşgul etmiyoruz.
        extracted_folder_path = await run_in_threadpool(
            download_repo, request.github_url
        )
        source_files = get_code_files_from_repo(extracted_folder_path)
        tasks = []

        # Groq sunucuları hızlı olduğu için aynı anda en fazla 5 analiz
        # görevinin eş zamanlı çalışmasına izin veren bir semafor oluşturuyoruz.
        sem = asyncio.Semaphore(5)

        async def analyze_with_semaphore(chunk, file_name):
            """Bir kod parçasını Groq'a kontrollü biçimde gönderir."""
            # Semaforda yer açılana kadar bekler; bloktan çıkınca hakkı otomatik bırakır.
            async with sem:
                # Her istekten önce kısa süre bekleyerek Groq API üzerindeki yükü dengeleriz.
                await asyncio.sleep(1)
                return await analyze_code_chunk_async(chunk, file_name)

        # Her kod parçası için bir asenkron görev hazırlıyoruz. Görevler aşağıdaki
        # asyncio.gather çağrısında başlatılacak, ancak semafor sayesinde aynı anda
        # en fazla 5 tanesi Groq API'ye istek gönderecek.
        for file_path, file_content in source_files.items():
            relative_file_name = Path(file_path).relative_to(
                Path(extracted_folder_path)
            ).as_posix()
            character_offset = 0

            for code_part in chunk_code(file_content):
                # Karakter bazlı parçalamada da özgün satır numarasını hesaplıyoruz.
                start_line = file_content.count("\n", 0, character_offset) + 1
                line_break_count = code_part.count("\n")
                end_line = start_line + line_break_count
                if code_part.endswith("\n") and end_line > start_line:
                    end_line -= 1

                tasks.append(
                    analyze_with_semaphore(code_part, relative_file_name)
                )
                character_offset += len(code_part)

        # Hazırlanan tüm Groq isteklerini eş zamanlı başlatıp tamamlanmalarını
        # bekliyoruz. Hiç kod parçası yoksa gather boş bir liste döndürür.
        results = await asyncio.gather(*tasks)

        # Her görevden dönen zafiyet listesini tek bir ana listede birleştiriyoruz.
        all_vulnerabilities = []
        for findings in results:
            all_vulnerabilities.extend(findings)

        # Analiz tamamlandıktan sonra bütün bulguları tek işlem içinde
        # veritabanına ekliyoruz. Böylece commit başarısız olursa yarım kayıt
        # oluşmasının önüne geçebiliriz.
        try:
            for finding in all_vulnerabilities:
                vulnerability = models.Vulnerability(
                    repo_url=request.github_url,
                    file_name=str(finding.get("file_name", "Bilinmeyen")),
                    vulnerability_name=str(finding.get("name", "Bilinmeyen")),
                    line_number=str(finding.get("line_number", "Bilinmeyen")),
                    suggestion=str(
                        finding.get("recommendation", "Manuel inceleme yapın.")
                    ),
                )
                db.add(vulnerability)

            # Oturuma eklenen tüm zafiyetleri PostgreSQL'e kalıcı olarak yazıyoruz.
            db.commit()
        except Exception as database_error:
            # Hata durumunda bekleyen işlemleri geri alarak oturumu yeniden
            # kullanılabilir ve veritabanını tutarlı durumda bırakıyoruz.
            db.rollback()
            raise RuntimeError(
                f"Zafiyetler veritabanına kaydedilemedi: {database_error}"
            ) from database_error

        return {
            "taranan_dosya_sayisi": len(source_files),
            "bulgular": all_vulnerabilities,
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Analiz sırasında bir hata oluştu: {error}",
        ) from error