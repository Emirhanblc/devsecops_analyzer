# Türkçe forumlar

Technopat, Donanımhaber veya benzeri bir yazılım bölümü için. Aynı metni aynı gün birkaç foruma yapıştırmayın. Bir yerde bırakın, gelen soruya orada cevap verin.

Parola ve API anahtarı yazmayın. Kurulum `.env` üzerinden gidiyor; okuyan kişi anahtarı kendisi koyar.

## Başlık

```
Herkese açık GitHub reposunu OWASP için tarayan küçük bir araç (FastAPI + Groq)
```

## Mesaj

```
Selam,

Kod incelemesi bizde genelde PR açıldıktan sonra başlıyor. O noktada bariz bir SQL Injection çoktan dalda olmuş oluyor. Onu merge’den önce göreyim diye küçük bir tarayıcı yazdım: DevSecOps Analyzer.

Ne yapıyor: herkese açık bir GitHub adresini alıyor, varsayılan dalı zip olarak indiriyor (token yok, private repo yok). Kaynak dosyaları 8000 karakterlik parçalara bölüp Groq’daki bir sohbet modeline soruyor. Modelden yalnızca kritik ve yüksek OWASP bulgusu istiyorum, cevap JSON olmak zorunda. Panelde zafiyet adı, dosya, satır ve kısa bir düzeltme önerisi çıkıyor. Aynı kayıtlar Postgres’te duruyor.

CI tarafında iki iş var, ikincisi birincisi bitince çalışıyor. Sebep Groq’un dakikalık token limiti; ikisi birden gidince 429 yemek kolay.

1. python scan.py — bu reponun kendi uygulama koduna bakıyor. Bulgu varsa veya API çağrısı düşerse pipeline kırmızı. API hatasını “temiz tarama” saymıyor.
2. python scan.py --fixture — yalnızca test_vuln.py dosyasına bakıyor. O dosya bilerek zafiyetli, içine SQL’i f-string ile gömen bir örnek koydum. Model SQL Injection derse iş yeşil, demezse kırmızı.

Yani sürekli kırmızı bir rozet “proje bozuk” diye durmasın istedim. Yeşil rozet “uygulama kodu temiz ve tarayıcı bildiğimiz açığı hâlâ görüyor” desin.

Sınırını da yazayım ki abartmış olmayayım. Bu Semgrep ya da CodeQL değil. Bulgular model çıktısı; satır numarası da modelin tahmini. Sessiz bir rapor “repo güvenli” demek değil, çünkü orta ve düşük seviye hiç sorulmuyor. Çok büyük repolarda Groq limiti yüzünden tarama uzayabiliyor.

Çalıştırmak için Docker ve bir Groq anahtarı yetiyor:

    git clone https://github.com/Emirhanblc/devsecops_analyzer.git
    cd devsecops_analyzer
    cp .env.example .env

.env içine GROQ_API_KEY yazın. Sonra:

    docker compose up --build

Arayüz: http://localhost:8080
Panel Türkçe.

Kaynak: https://github.com/Emirhanblc/devsecops_analyzer

Deneyen olursa, özellikle büyük bir repoda nerede tıkandığını yazarsa sevinirim.
```
