# LinkedIn

Gönderiye kapak olarak `docs/images/social-preview.png` ekleyin. Metindeki linkin önizlemesi, GitHub deposunun sosyal kapağı yüklendikten sonra o görseli kullanır. Hashtag satırı metnin parçasıdır; ayrıca eklemeyin.

Aşağıdaki blokların dışındaki satırlar gönderiye girmez.

## Türkçe gönderi

```
Kod incelemesi çoğu ekipte pull request açıldıktan sonra başlıyor. SQL Injection o sırada çoktan dalda oluyor.

DevSecOps Analyzer, herkese açık bir GitHub deposunu Groq üzerindeki bir sohbet modeliyle tarıyor. Yalnızca OWASP Top 10 kapsamındaki kritik ve yüksek bulguları bırakıyor. Her bulgu dosya, satır ve kısa bir düzeltme önerisiyle panele yazılıyor. Aynı kontrol GitHub Actions içinde her push ve pull request’te çalışıyor. Uygulama kodunda bulgu varsa pipeline kırmızıya düşüyor.

Herkese açık varsayılan dal zip olarak iniyor; private repo bu sürümde yok. Kaynak 8000 karakterlik parçalara ayrılıyor. Panel Türkçe: URL’yi yapıştırıyorsunuz, taranan dosya sayısı ve bulgular tabloda kalıyor.

Kasıtlı SQL Injection örneği ayrı bir işte duruyor. Tarayıcı onu yakalarsa iş yeşil, yakalayamazsa kırmızı. Rozet “her şey yolunda” demiyor. “Uygulama kodu temiz ve tarayıcı bilinen açığı görüyor” diyor.

Docker ve bir Groq anahtarı yetiyor. Bu Semgrep değil; modelin işaret ettiği satırı açıp okumak hâlâ sizde.

Yığın: Python, FastAPI, PostgreSQL, Docker, Groq, GitHub Actions.

https://github.com/Emirhanblc/devsecops_analyzer

#DevSecOps #AppSec #OWASP #Python #GitHubActions #LLM
```

## English post

```
Code review usually starts after the pull request exists. By then a SQL injection is already on the branch.

DevSecOps Analyzer scans a public GitHub repo with a Groq chat model and keeps only critical and high OWASP findings, each with a file, a line, and a short fix. The same check runs on every push and pull request. A finding in the application code fails the build.

A second job scans an intentional SQL injection and passes only when the model reports it. The green badge means the app is clean and the scanner still sees the known bug.

Stack: Python, FastAPI, PostgreSQL, Docker, Groq, GitHub Actions.

https://github.com/Emirhanblc/devsecops_analyzer

#DevSecOps #AppSec #OWASP #Python #GitHubActions #LLM
```
