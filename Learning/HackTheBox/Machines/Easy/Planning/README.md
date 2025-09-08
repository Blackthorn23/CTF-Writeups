# HackTheBox - Planning (Linux - Easy)
---

## 🕵️‍♂️ 1. Machine Information
![Machine Info](picture1.png)

- **IP Address**: `10.10.11.68`
- **Difficulty**: Easy
- **Points**: 20 (User + Root)

---

## 🔎 2. Enumeration
### Nmap Scan
![Nmap](picture2.png)

- Open ports:
  - `22/tcp` → OpenSSH 9.6p1
  - `80/tcp` → Nginx 1.24.0
- The site redirects to `planning.htb`.

### Add Domain to Hosts
![Hosts File](picture3.png)

Added:
```
10.10.11.68 planning.htb
```

---

## 🌐 3. Web Enumeration
### Main Website
![Main Website](picture4.png)

The domain hosts an **EdukaTe** educational template.

### VHost Enumeration with Gobuster
![Gobuster](picture5.png)

Discovered subdomain:
```
grafana.planning.htb
```

### Update Hosts File
![Hosts Update](picture6.png)

Added:
```
10.10.11.68 grafana.planning.htb
```

---

## 📊 4. Grafana Service
### Login Page
![Grafana Login](picture7.png)

Visiting `grafana.planning.htb` reveals a **Grafana v11.0.0** login.

### Default Credentials
![Grafana Creds](picture8.png)

Using provided credentials:
```
admin : 0D5oT70Fq13EvB5r
```

### Grafana Dashboard
![Grafana Dashboard](picture9.png)

Successfully logged into Grafana.

---

## 💥 5. Exploitation (Grafana RCE)
### Vulnerability Reference
![Exploit Repo](picture10.png)

The machine is vulnerable to **CVE-2024-9264** – Grafana SQL Expressions RCE.

### Clone Exploit
![Exploit Clone](picture11.png)

Exploit repo cloned from GitHub.

### Netcat Listener
![Netcat Listener](picture12.png)

Started a listener on port `4444`.

### Run Exploit
![Exploit Run](picture13.png)

Executed PoC with reverse shell payload.

### Shell Access
![Root Shell](picture14.png)

Reverse shell obtained → running as **root** in Grafana’s container environment.

---

## 🧩 6. Privilege Escalation
### LinPEAS Enumeration
![Linpeas](picture15.png)

Uploaded and ran **LinPEAS** for privilege escalation hints.

### Environment Variables Leak
![Creds Found](picture16.png)

Found credentials in environment variables:
```
User: enzo
Password: RioTeCRANdenTANT!
```

### SSH as Enzo
![SSH Enzo](picture17.png)

Logged in via SSH with the credentials.

### User Flag
![User Flag](picture18.png)

```
cat user.txt
de2b9737d22fcca82157a937bdac7a2c
```

### Sudo Privilege
![Sudo Priv](picture19.png)

`enzo` has `NOPASSWD: ALL` → full root access.

### Root Flag
![Root Flag](picture20.png)

```
cat /root/root.txt
ea12bf8f9bf55b0c5e3140cd30f59d59
```

---

## 🎉 7. Pwned!
![Pwned](picture21.png)

- **User pwned** ✅  
- **Root pwned** ✅  
- **Points earned**: 30  

---

## 📝 Summary
- **Initial Access**: Grafana subdomain enumeration → login with given credentials.  
- **Exploitation**: CVE-2024-9264 RCE → reverse shell as root (Grafana container).  
- **Privilege Escalation**: Exposed credentials → SSH as enzo → `sudo NOPASSWD:ALL` → full root.  

---

## 📌 Tags
```
HackTheBox, HTB, Planning, Linux, Easy, Walkthrough, Grafana, CVE-2024-9264, RCE, Privilege Escalation, CTF
```
