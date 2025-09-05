# 🤖 HackTheBox - Artificial

![Artificial Banner](picture1.png)



## 🎯 Overview

Artificial is an Easy-rated Linux machine on HackTheBox that leverages **artificial intelligence** themes and technologies. This machine appears to be newly released (June 2025) and has gained significant attention from the community with thousands of successful solves.

## 🔍 Reconnaissance

### Initial Ping scan

Let's start by pinging the TARGET IP
![Machine Preview](picture2.png)

### Initial Nmap Scan

Now perform a basic port scan to identify open services:

```bash
sudo nmap -sVC <TARGET IP>
```

![Initial Nmap Scan](picture3.png)

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.x (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

### Host File Configuration

This allowed me to access the website directly by visiting http://artificial.htb.

![Full Port Scan](picture4.png)

### Service Enumeration

#### HTTP Service (Port 80)

Let's explore the web application (Login page):

![Web Application Homepage](picture5.png)

Create a user and login using the credentials:

![Gobuster Results](picture6.png)

After logging in, I was redirected to a dashboard that allows managing and uploading AI models (But with a little requirements):

![Whatweb Results](picture7.png)

#### AI Model Requirements 

The application clearly required uploaded models to be built with TensorFlow CPU version 2.13.1. To assist with this, it even provided a reference Dockerfile for building compatible environments:

![Wappalyzer Technology Stack](picture8.png)

## 🚪 Gaining Initial Access

### Vulnerability Discovery

I found a public repository demonstrating how to abuse TensorFlow’s model loading mechanism for RCE https://github.com/Splinter0/tensorflow-rce/.

**Step 1: Cloning the Exploit Repository**

I cloned the repo and verified the exploit scripts were available:

![Vulnerability Discovery](picture9.png)

![AI Interface Analysis](picture10.png)

**Step 2: Writing the Malicious Exploit**

Using the exploit.py script that creates a malicious .h5 TensorFlow model containing a reverse shell payload, I changed the IP and PORT to my attacker machine.

![Shell Access](picture12.png)
![Shell Access](picture13.png)

**Step 3: Building the Docker Image**

I copied the prepared Dockerfile into the repo and built the container, then I launched a container with a mounted shared volume:

![Payload Crafting](picture11.png)

**Step 4: Generating the Malicious Model**

I executed the script to generate exploit.h5:

![Initial Shell Commands](picture14.png)

**Step 5: Setting up a Listener**

On my attacking machine, I set up a Netcat listener on port 4444 to catch the reverse shell:

![Initial Shell Commands](picture17.png)

**Step 6: Uploading the Malicious Model**

Back on the target’s dashboard, I uploaded the crafted exploit.h5 model and execute it by (View Predictions):

![Initial Shell Commands](picture15.png)
![Initial Shell Commands](picture16.png)

**Accessing User Account:**

Wolla! We gained the initial access to the system:

![User Account Access](picture18.png)

### 🏆 User Flag

**Step 1: Exploring the Application Directory**

After gaining a shell, I enumerated the /app directory and found an SQLite database inside the instance folder.

![User Flag](picture19.png)

Step 2: Extracting User Credentials
I opened the database and dumped the contents of the user table, the database contained usernames, emails, and MD5 password hashes.

![LinPEAS Results](picture20.png)

**Step 3: Preparing Hashes for Cracking**

I copied the database result into a text file (hashes.txt) and remain only the hashes.

![Sudo Permissions](picture21.png)

![SUID Binaries](picture22.png)

**Step 4: Cracking Hashes with John the Ripper**

Using john with the rockyou.txt wordlist, I successfully cracked 4 out of 7 passwords.

```bash
gael : mattp005numbertwo

mark : marvinnarak043414036

john : john

kali : kali
```

![Root Processes](picture23.png)

**Step 5: Privilege Escalation to User**

I switched user to gael using the cracked credentials and retrieved the user.txt flag in the home directory.

![Payload Execution](picture25.png)

**User Flag:** `239b3032f78802d747f220031daec97e`

## 🏁 Root Flag

**Step 1: SSH into the server**
SSH as User gael:

![Root Access](picture26.png)

But User gael is not in the sudo group:

![Root Access](picture27.png)

**Step 2: Escalation Enumeration with LinPEAS**
After securing the user foothold, I transferred and executed LinPEAS to enumerate privilege escalation vectors.

![Root Access](picture28.png)

![Root Directory](picture29.png)

During the scan, LinPEAS highlighted a suspicious file in /var/backups — a large archive owned by root.

![Root Directory](picture30.png)

![Root Directory](picture31.png)

**Step 3: Downloading the Backup Archive**
Inside /var/backups, I found backrest_backup.tar.gz. To analyze it locally, I started a Python HTTP server and exfiltrated the file to my attacker machine.

![Root Directory](picture32.png)

**Step 4: Extracting Backup Contents**
I extracted the archive and discovered configuration files, SQLite databases, and logs. Among these, a file named config.json stood out.

![Root Directory](picture34.png)

**Step 5: Finding Credentials**
Inspecting the config file revealed credentials for a privileged user backrest_root, with the password stored as a crypt hash.

![Root Directory](picture34.png)

**Step 6: Cracking the Hash**
I extracted the bcrypt hash, saved it into backrest.hash, and used John the Ripper with the rockyou.txt wordlist to crack it.

![Root Directory](picture35.png)

The cracked password was:
```bash
!@#$%^
```
**Step 7: Enumerating Internal Services**
After gaining the credentials for the backrest, I checked for running services with:

```bash
ss -tulpn
```
![Root Directory](picture36.png)

I found several interesting ports bound to localhost only, including 5000 (Flask app) and 9898 (Backrest panel).

**Step 8: SSH Port Forwarding to Access Services**

To reach these internal services, I used SSH tunneling:

```bash
ssh -L 5000:127.0.0.1:5000 gael@<TARGET IP>
ssh -L 9898:127.0.0.1:9898 gael@<TARGET IP>
```

![Root Directory](picture37.png)
![Root Directory](picture39.png)

**Step 9: Visit the websites**

![Root Directory](picture38.png)
![Root Directory](picture40.png)

**Step 10: Logging into Backrest**
I logged in using the credentials backrest_root.

![Root Directory](picture41.png)

**Step 11: Creating a Repository**
Using restic, I created a new repository at /home/gael/myrepo and set a password.

```bash
/opt/backrest/restic -r /home/gael/myrepo init
/opt/backrest/restic -r /home/gael/myrepo key passwd
```
![Root Directory](picture42.png)

Then I linked it inside Backrest’s web panel:

![Root Directory](picture43.png)

**Step 12: Backing up /root Directory**

From the Backrest web UI, I executed a backup command to archive /root.

![Root Directory](picture44.png)

**Step 13: Accessing the Snapshot**
Inside the repo, I located the snapshot:

![Root Directory](picture45.png)

Then from the Backrest web UI, I executed a list command on the snapshot id.
![Root Directory](picture46.png)

Dumping the snapshot files revealed the root.txt flag. 🎉

![Root Directory](picture47.png)
![Root Directory](picture48.png)
> **⚠️ Disclaimer:** This writeup is for educational purposes only. Always ensure you have proper authorization before testing security tools and techniques. The author is not responsible for any misuse of the information provided.

**🎯 Machine Completed:** `5 Sep 2025`
**🏆 Flags Captured:** `2/2`