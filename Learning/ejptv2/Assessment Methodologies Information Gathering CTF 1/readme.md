# EJPT v2 - Assessment Methodologies: Information### Step 3: Perform nmap 
![Directory Analysis](picture8.png)

<details>
<summary>Click to expand</summary>

With connectivity confirmed, the next step was to run an Nmap scan on the target to identify open ports and running services. Nmap (Network Mapper) is an essential reconnaissance tool that provides detailed information about the target's network exposure.

The basic Nmap scan command used was:
```bash
nmap target_ip
```

For more comprehensive results, additional scan options can be employed:
```bash
# Service version detection
nmap -sV target_ip

# Service and script scanning
nmap -sC -sV target_ip

# Scan all ports
nmap -p- target_ip
```

The Nmap scan results revealed:
- **Open ports**: Identified which services are accessible
- **Service versions**: Determined the specific versions of running services
- **Operating system hints**: Gathered clues about the target's OS
- **Service banners**: Obtained additional service information

During this enumeration phase, I discovered that **FLAG 2** was embedded within the Nmap scan results or service banner information, demonstrating how network reconnaissance can directly lead to flag discovery in CTF environments.

This scan provided the foundation for understanding the target's attack surface and guided subsequent enumeration efforts toward the identified services.

</details>g CTF 1

## Overview
This repository contains a detailed walkthrough of the Information Gathering CTF challenge from the eLearnSecurity Junior Penetration Tester (EJPTv2) certification course. This CTF focuses on fundamental assessment methodologies and information gathering techniques essential for penetration testing.

## Challenge Description
This lab focuses on information gathering and reconnaissance techniques to analyze a target website. Participants will explore various aspects of the website to uncover potential vulnerabilities, sensitive files, and misconfigurations. By leveraging investigative skills, they will learn how to identify critical information that could assist in further penetration testing or exploitation.

## Prerequisites
- Basic understanding of networking concepts
- Familiarity with Linux command line
- Knowledge of common penetration testing tools
- Understanding of TCP/IP protocols

## Tools Used
- Nmap
- Dirb
- Httrack

## Lab Overview 
![Network Discovery](picture1.png)
![Port Scanning](picture2.png)

Carefully understand what each of the flag required tasks and where could they be located.

![Service Enumeration](picture3.png)

## Walkthrough

### Step 1: Running the lab enviroment
![Web Application Discovery](picture4.png)

<details> <summary>Click to expand</summary>

The first step was to launch the provided lab environment. This setup creates the controlled workspace where all subsequent testing and analysis will take place, ensuring a consistent and reproducible environment for the assessment.

</details>


### Step 2: Pinging the target website
![Pinging Target](picture5.png)

<details>
<summary>Click to expand</summary>

As a preliminary step, I performed a simple ping test to check whether the target system was reachable. This serves as a quick “handshake” to confirm that the host is active and responding before moving on to deeper enumeration. Establishing this baseline connectivity ensures that subsequent tests can be carried out smoothly and without unnecessary interruptions.

</details>

### Step 3: Perform nmap scanning 
![Directory Analysis](picture8.png)

<details>
<summary>Click to expand</summary>

With connectivity confirmed, the next step was to run an Nmap scan on the target. This process helps identify open ports, available services, and potential entry points for further exploration. The scan provides a clearer picture of the system’s surface exposure, forming the foundation for deeper enumeration and vulnerability assessment This reveal **FLAG 2**.

</details>

### Step 4: Visiting the website
![Initial Reconnaissance](picture6.png)

<details>
<summary>Click to expand - Initial reconnaissance techniques</summary>

Following the Nmap scan, it was clear that the target was running a web service on port 80. Navigating to the IP address in a browser revealed a WordPress-based website. This initial reconnaissance provided valuable insight into the type of application in use, setting the stage for further enumeration of potential vulnerabilities specific to WordPress.

</details>

### Step 5: Inspecting robots.txt
![Directory Enumeration](picture7.png)

<details>
<summary>Click to expand</summary>

Following the initial website reconnaissance, I examined the robots.txt file located at the root of the server. The robots.txt file is a standard used by websites to communicate with web crawlers and search engines, providing instructions about which parts of the site should or should not be indexed.

To access the robots.txt file, I navigated to:
```
http://target_ip/robots.txt
```

The robots.txt file typically contains:
- **Disallow directives**: Paths that search engines should not crawl
- **Allow directives**: Explicitly permitted paths
- **Sitemap locations**: References to XML sitemaps
- **Crawl-delay settings**: Instructions for crawler behavior

This file is particularly valuable during reconnaissance because:
1. **Hidden directories**: Often reveals directories administrators want to keep private
2. **Sensitive paths**: May point to admin panels, backup directories, or development areas
3. **Site structure insights**: Provides a roadmap of important website sections
4. **Security through obscurity failures**: Exposes paths meant to be hidden

Upon examining the robots.txt file, I discovered **FLAG 1**.

</details>

### Step 6: Directory enumeration with Dirb
![Content Discovery](picture9.png)

<details>
<summary>Click to expand</summary>

Using Dirb to discover hidden directories and files on the target website. This automated tool helps identify potential entry points and sensitive resources that may not be linked from the main pages.

</details>

### Step 7: Directory browsing on where files were stored
![Technology Identification](picture10.png)
![Source Code Analysis](picture11.png)
<details>
<summary>Click to expand</summary>

After discovering directories through the Dirb enumeration, the next crucial step was to manually browse through the identified directories to examine their contents. This involved systematically navigating to each discovered directory and analyzing what files and subdirectories were accessible. 

During this exploration, I found `/wp-content/uploads` directory which is a common WordPress directory where uploaded files are stored. This directory contains the **FLAG 3**.
</details>

### Step 8: An overlooked backup file
![Robots Analysis](picture13.png)

<details>
<summary>Click to expand</summary>

Asking chatgpt, I discovered a backup file used by wordpress named `wp-config.bak`/`wp-config.php.bak`

These backup files can have various naming conventions such as:
- `.bak` extensions (e.g., `config.php.bak`)
- Tilde suffix (e.g., `index.php~`)
- `.old` extensions (e.g., `database.sql.old`)
- Date-based naming (e.g., `backup_2023.zip`)
</details>

### Step 9: Opening the backup file 
![HTTP Headers](picture12.png)

![Parameter Analysis](picture15.png)

<details>
<summary>Click to expand</summary>

After discovering the backup file `wp-config.php.bak`, the next step was to access and examine its contents. When attempting to open this file through the web browser, it automatically triggered a download of the backup file to the local machine.

The `wp-config.php` file is particularly sensitive in WordPress installations as it contains critical configuration information including:
- Database connection credentials
- Authentication keys and salts
- Table prefix information
- Debug settings
- Security keys

Using the `cat` command to examine the downloaded backup file revealed its complete contents, including database credentials and other sensitive configuration data. Most importantly, this backup file contained **Flag 4**.

</details>


### Step 10: Download the website content using httrack
![Cookie Analysis](picture18.png)

![Flag Discovery](picture19.png)

<details>
<summary>Click to expand</summary>

To perform a comprehensive analysis of the website and ensure no hidden content was missed, I used HTTrack to create a complete local mirror of the target website. HTTrack is a powerful website copying utility that downloads entire websites to local storage, preserving the directory structure and all linked files.

The HTTrack command used was:
```bash
httrack http://target_ip/ -O /path/to/output/directory/
```

This process systematically downloads:
- All HTML pages and their content
- Images, CSS, and JavaScript files
- Linked documents and media files
- Directory structures and file hierarchies
- Hidden or referenced files that might not be discoverable through manual browsing

```bash
# Search for FLAG5
grep -i "FLAG5" -R target.ine.local/
```

This systematic analysis of the mirrored content revealed **Flag 5**.
</details>

## Key Learning Objectives

1. **Network Reconnaissance**: Understanding how to systematically discover and map network infrastructure
2. **Service Enumeration**: Learning to identify and enumerate services running on discovered hosts
3. **Vulnerability Identification**: Developing skills to identify potential security weaknesses
4. **Information Analysis**: Learning to analyze gathered information to identify attack vectors
5. **Documentation**: Understanding the importance of proper documentation in penetration testing


## Conclusion

This CTF challenge provides comprehensive hands-on experience with information gathering and assessment methodologies essential for penetration testing. The systematic approach demonstrated here forms the foundation for more advanced penetration testing techniques covered in the EJPT certification.

## Notes

- Screenshots and detailed command outputs are preserved for reference
- Each step builds upon the previous, demonstrating a methodical approach to information gathering
- The techniques shown here are fundamental to professional penetration testing engagements

---

**Disclaimer**: This content is for educational purposes only. Always ensure you have proper authorization before conducting security assessments on any systems you do not own.