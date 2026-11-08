import os

# Varsayılan olarak taranacak kaynak kod uzantıları.
DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".html", ".php", ".cs"
}

# Bağımlılık, test, dokümantasyon ve derleme klasörleri güvenlik analizinin
# odağını dağıtır ve gereksiz Gemini istekleri oluşturur.
EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    "tests",
    "test",
    "docs",
    "docs_src",
    "examples",
}

MAX_FILE_SIZE = 500_000

def get_code_files_from_repo(repo_path: str) -> dict[str, str]:
    """
    İndirilen repo dizinindeki varsayılan kod dosyalarını bulur ve içeriklerini okur.
    Döndürülen değer: { "dosya_yolu": "dosya_içeriği" } şeklinde bir sözlüktür.
    """
    code_files = {}

    # os.walk ile klasörün içindeki tüm dosya ve alt klasörleri geziyoruz
    for root, directories, files in os.walk(repo_path):
        # os.walk'ın bu klasörlere hiç girmemesini sağlayarak taramayı hızlandırırız.
        directories[:] = [
            directory
            for directory in directories
            if directory.lower() not in EXCLUDED_DIRECTORIES
        ]

        for file in files:
            # Dosyanın uzantısını alıyoruz (Örn: .py)
            _, ext = os.path.splitext(file)
            
            # Eğer uzantı varsayılan dillerimizden biriyse okuyoruz
            if ext.lower() in DEFAULT_EXTENSIONS:
                file_path = os.path.join(root, file)

                # Çok büyük veya küçültülmüş dosyalar aşırı API tüketimine yol açabilir.
                if file.endswith((".min.js", ".min.css")):
                    continue

                try:
                    if os.path.getsize(file_path) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                
                try:
                    # Dosyayı UTF-8 formatında okumaya çalışıyoruz
                    with open(file_path, "r", encoding="utf-8") as f:
                        code_files[file_path] = f.read()
                except Exception as e:
                    # Okunamayan (bozuk veya farklı formatlı) dosyaları kod çökmesin diye atlıyoruz
                    print(f"Uyarı: {file_path} okunamadı. Hata: {e}")
                    
    return code_files

def chunk_code(code_text: str, max_chars: int = 8000) -> list[str]:
    """
    Uzun kod metinlerini yapay zekanın sınırlarını aşmamak için parçalara böler.
    code_text: Parçalanacak kod metni
    max_chars: Her bir parçanın maksimum karakter sayısı
    """
    chunks = []
    
    # Kodu max_chars uzunluğunda parçalara ayırarak listeye ekliyoruz
    for i in range(0, len(code_text), max_chars):
        chunks.append(code_text[i:i+max_chars])
        
    return chunks