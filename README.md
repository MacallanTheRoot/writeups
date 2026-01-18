<div align="center">
  <a href="#en">🇺🇸 English</a> | <a href="#tr">🇹🇷 Türkçe</a>
</div>

<a name="en"></a>
# 🛡️ Security Penetration Testing Writeups
### Comprehensive Technical Security Assessments & Exploitation Documentation

![Report Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)
![Languages](https://img.shields.io/badge/languages-2-blue?style=for-the-badge)
![Target Systems](https://img.shields.io/badge/targets-2-red?style=for-the-badge)
![Last Updated](https://img.shields.io/badge/updated-Jan%202026-orange?style=for-the-badge)

---

## English

### Overview

### Overview

This repository contains comprehensive penetration testing reports and writeups documenting security assessments conducted on various target systems. Each writeup includes detailed technical analysis, exploitation methodologies, and remediation recommendations.

### Contents

#### 🔍 [HackViser Assessments](/hackviser/)

##### 1. **Explorer** 
- **Type:** Penetration Testing Report
- **Target System:** alexriveraexplorer.hv (172.20.36.127)
- **Difficulty:** Easy
- **Files:**
  - [English Report](/hackviser/explorer/Explorer_writeup_EN.md)
  - [Turkish Report](/hackviser/explorer/Explorer_writeup_TR.md)
  - [Original Report](/hackviser/explorer/explorer%20writeup.md)

**Key Vulnerabilities:**
- Information disclosure via SNMP with default community string
- Cleartext credentials exposure through SNMP OID enumeration
- Sudo misconfiguration on systemctl binary (NOPASSWD)
- Plaintext storage of threat actor credentials and malware

---

##### 2. **PasteZone**
- **Type:** Penetration Testing Report
- **Target System:** pastezone.hv (172.20.5.99)
- **Difficulty:** Easy
- **Files:**
  - [English Report](/hackviser/pastezone/Pastezone%20writeup.md)
  - [Turkish Report](/hackviser/pastezone/Pastezone%20writeup%20tr.md)

**Key Vulnerabilities:**
- Server-Side Template Injection (SSTI) in Twig template engine
- Remote Code Execution (RCE) via template manipulation
- Improper Linux capability assignment on PHP binary (cap_setuid+ep)
- Exposed database with plaintext credentials and user information
- Privilege escalation to root access

---

### Report Structure

Each penetration testing report follows a standardized format:

1. **Executive Summary** - Overview of findings and key vulnerabilities
2. **Enumeration** - Reconnaissance and information gathering techniques
3. **Exploitation** - Technical breakdown of vulnerability exploitation
4. **Privilege Escalation** - Methods used to gain elevated access
5. **Loot/Flags** - Extracted sensitive data and evidence
6. **Remediation** - Recommended security improvements and fixes

---

### Technical Highlights

- **SNMP Enumeration:** Exploitation of default community strings and OID tree walking
- **Template Injection:** PHP Twig SSTI vulnerability chain leading to RCE
- **Linux Capabilities:** Exploitation of improper capability assignments for privilege escalation
- **Sudo Misconfiguration:** Bypass of privilege restrictions through misconfigured binaries

---

### Usage

Each writeup is self-contained and can be read independently. The reports include:
- Step-by-step exploitation commands
- Technical explanations of vulnerability mechanics
- Screenshots and output examples
- Complete exploitation chain documentation

---

### Security Disclaimer

These writeups are for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting penetration tests.

---

<br>
<br>
<br>

---

<a name="tr"></a>
# 🛡️ Güvenlik Sızma Testi Yazıları
### Kapsamlı Teknik Güvenlik Değerlendirmeleri & İstismar Belgelendirmesi

![Rapor Durumu](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)
![Diller](https://img.shields.io/badge/languages-2-blue?style=for-the-badge)
![Hedef Sistemler](https://img.shields.io/badge/targets-2-red?style=for-the-badge)
![Son Güncelleme](https://img.shields.io/badge/updated-Oca%202026-orange?style=for-the-badge)

---

## Türkçe

### Genel Bilgi

Bu depo, çeşitli hedef sistemler üzerinde yürütülen güvenlik değerlendirmelerini belgelendiren kapsamlı sızma testi raporları ve yazıları içermektedir. Her yazı, ayrıntılı teknik analiz, istismar metodolojileri ve iyileştirme önerilerini içermektedir.

### İçerik

#### 🔍 [HackViser Değerlendirmeleri](/hackviser/)

##### 1. **Explorer**
- **Tür:** Sızma Testi Raporu
- **Hedef Sistem:** alexriveraexplorer.hv (172.20.36.127)
- **Zorluk Seviyesi:** Kolay
- **Dosyalar:**
  - [İngilizce Rapor](/hackviser/explorer/Explorer_writeup_EN.md)
  - [Türkçe Rapor](/hackviser/explorer/Explorer_writeup_TR.md)
  - [Orijinal Rapor](/hackviser/explorer/explorer%20writeup.md)

**Temel Zafiyetler:**
- SNMP hizmetinde varsayılan topluluk dizesinin açığa çıkarılması
- SNMP OID ağacı üzerinden şifrenin açık metin olarak bulunması
- systemctl ikilisinde sudo yanlış yapılandırması (NOPASSWD)
- Tehdit aktörü kimlik bilgileri ve zararlıların açık metin olarak depolanması

---

##### 2. **PasteZone**
- **Tür:** Sızma Testi Raporu
- **Hedef Sistem:** pastezone.hv (172.20.5.99)
- **Zorluk Seviyesi:** Kolay
- **Dosyalar:**
  - [İngilizce Rapor](/hackviser/pastezone/Pastezone%20writeup.md)
  - [Türkçe Rapor](/hackviser/pastezone/Pastezone%20writeup%20tr.md)

**Temel Zafiyetler:**
- Twig şablon motorunda Sunucu Tarafı Şablon İnjeksiyonu (SSTI)
- Şablon manipülasyonu aracılığıyla Uzaktan Kod Yürütme (RCE)
- PHP ikilisinde yanlış Linux yeteneği ataması (cap_setuid+ep)
- Açık metin kimlik bilgileri ve kullanıcı bilgileri içeren açığa çıkarılmış veritabanı
- Root erişimi için ayrıcalık yükseltme

---

### Rapor Yapısı

Her sızma testi raporu standartlaştırılmış bir format izler:

1. **Yönetim Özeti** - Bulgular ve temel zafiyetlere genel bakış
2. **Numaralandırma** - İzleme ve bilgi toplama teknikleri
3. **İstismar** - Zafiyet istismarının teknik analizi
4. **Ayrıcalık Yükseltme** - Yüksek erişim kazanmak için kullanılan yöntemler
5. **Ele Geçirilen Veriler/Bayraklar** - Çıkarılan hassas veriler ve kanıtlar
6. **Iyileştirme** - Önerilen güvenlik geliştirmeleri ve düzeltmeler

---

### Teknik Vurgular

- **SNMP Numaralandırması:** Varsayılan topluluk dizelerinin ve OID ağacı yürüyüşünün istismarı
- **Şablon İnjeksiyonu:** RCE'ye yönelik PHP Twig SSTI zafiyet zinciri
- **Linux Yetenekleri:** Ayrıcalık yükseltme için yanlış yetenek atamalarının istismarı
- **Sudo Yanlış Yapılandırması:** Yanlış yapılandırılmış ikililer aracılığıyla ayrıcalık sınırlamalarının aşılması

---

### Kullanım

Her yazı bağımsız olarak okunabilir. Raporlar şunları içermektedir:
- Adım adım istismar komutları
- Zafiyet mekaniğinin teknik açıklamaları
- Ekran görüntüleri ve çıktı örnekleri
- Tam istismar zinciri belgelendirmesi

---

### Güvenlik Uyarısı

Bu yazılar yalnızca eğitim ve yetkili güvenlik testi amaçları için tasarlanmıştır. Bilgisayar sistemlerine yetkisiz erişim yasa dışıdır. Sızma testleri gerçekleştirmeden önce her zaman uygun yetkilendirme alınız.

---

**Son Güncelleme**: 18 Ocak 2026
