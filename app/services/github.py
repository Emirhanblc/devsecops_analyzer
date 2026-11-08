import requests
import zipfile
import io
import os
import shutil

# Repoların indirileceği ana klasör yolu
TEMP_REPOS_DIR = "./temp_repos"

def download_repo(repo_url: str) -> str:
    """
    Verilen GitHub URL'sini kullanarak repoyu zip olarak indirir ve çıkartır.
    Döndürülen değer, kodların çıkartıldığı klasörün yoludur (path).
    """
    # 1. URL'yi temizle: Sondaki '/' işaretlerini kaldır
    clean_url = repo_url.rstrip("/")

    # Eğer URL '.git' ile bitiyorsa, son 4 karakteri (.git) kesip atıyoruz
    if clean_url.endswith(".git"):
        clean_url = clean_url[:-4]

    # URL'yi '/' karakterine göre parçalara ayırıyoruz
    parts = clean_url.split("/")

    # Geçerli bir GitHub linki olup olmadığını kontrol ediyoruz
    if len(parts) < 2 or "github.com" not in clean_url:
        raise ValueError("Geçersiz veya desteklenmeyen GitHub URL formatı.")
        
    owner = parts[-2]
    repo_name = parts[-1]
    
    # 2. GitHub API Zip indirme URL'si (Varsayılan branch'i indirir)
    api_url = f"https://api.github.com/repos/{owner}/{repo_name}/zipball"
    
    # 3. İsteği gönder
    response = requests.get(api_url)
    
    if response.status_code != 200:
        raise Exception(f"Repo indirilemedi. GitHub API Yanıt Kodu: {response.status_code}")
        
    # 4. Geçici klasörümüz yoksa oluşturalım
    os.makedirs(TEMP_REPOS_DIR, exist_ok=True)
    
    # Her repo için özel bir klasör ismi belirleyelim
    extract_path = os.path.join(TEMP_REPOS_DIR, f"{owner}_{repo_name}")
    
    # Eğer bu repo daha önce indirilmişse, çakışmayı önlemek için eski klasörü silelim
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
        
    # 5. Zip dosyasını hafızada okuyup diske çıkartalım
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        z.extractall(extract_path)
        
    return extract_path