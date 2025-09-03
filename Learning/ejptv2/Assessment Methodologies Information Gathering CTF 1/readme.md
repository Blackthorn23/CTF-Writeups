# EJPT v2 - Assessment Methodologies: Information Gathering CTF 1

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

The task is to find 5 flags by carefully enumerating the target website.

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

### Step 3: Perform nmap 
![Directory Analysis](picture8.png)

<details>
<summary>Click to expand</summary>

With connectivity confirmed, the next step was to run an Nmap scan on the target. This process helps identify open ports, available services, and potential entry points for further exploration. The scan provides a clearer picture of the system’s surface exposure, forming the foundation for deeper enumeration and vulnerability assessment.

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

A useful clue from the first flag hint. I examined the robots.txt file located at the root of the server. This file serves as a set of guidelines for search engines, essentially telling them what content to index and what to avoid.

</details>

### Step 6: Directory enumeration with Dirb
![Content Discovery](picture9.png)

<details>
<summary>Click to expand</summary>

Using Dirb to discover hidden directories and files on the target website. This automated tool helps identify potential entry points and sensitive resources that may not be linked from the main pages.

</details>

### Step 7: Web application technology identification
![Technology Identification](picture10.png)
![Source Code Analysis](picture11.png)
<details>
<summary>Click to expand</summary>

Identifying the specific technologies, frameworks, and versions used by the target web application. This information helps in understanding potential attack vectors and known vulnerabilities.

</details>

### Step 8: Robots.txt and sitemap analysis
![Robots Analysis](picture12.png)

<details>
<summary>Click to expand - Robots.txt and sitemap examination</summary>

Checking for robots.txt file and sitemaps to understand the website structure and identify directories or files that the website administrators don't want indexed by search engines.

</details>

### Step 10: HTTP headers and response analysis
![HTTP Headers](picture13.png)

<details>
<summary>Click to expand - HTTP response analysis</summary>

Analyzing HTTP headers to gather information about the web server, security headers, cookies, and other response details that might reveal security configurations or vulnerabilities.

</details>

### Step 11: Error page analysis and information disclosure
![Error Analysis](picture14.png)

<details>
<summary>Click to expand - Error page enumeration</summary>

Testing for custom error pages and analyzing error messages that might disclose sensitive information about the web application, database, or server configuration.

</details>

### Step 12: Hidden parameter and form analysis
![Parameter Analysis](picture15.png)

<details>
<summary>Click to expand - Form and parameter discovery</summary>

Identifying hidden form parameters, analyzing form submissions, and testing for parameter manipulation vulnerabilities that could lead to information disclosure.

</details>

### Step 13: Cookie and session analysis
![Cookie Analysis](picture16.png)

<details>
<summary>Click to expand - Cookie and session examination</summary>

Examining cookies and session management to understand how the application handles user sessions and whether there are any security weaknesses in session implementation.

</details>

### Step 14: SSL/TLS certificate analysis
![Certificate Analysis](picture17.png)

<details>
<summary>Click to expand - SSL certificate examination</summary>

Analyzing SSL/TLS certificates to gather information about the organization, validity periods, and potential certificate-related vulnerabilities or misconfigurations.

</details>

### Step 15: Social engineering and OSINT gathering
![OSINT Gathering](picture18.png)

<details>
<summary>Click to expand - Open source intelligence techniques</summary>

Gathering publicly available information about the target organization, employees, and infrastructure that could be useful for the assessment or social engineering attacks.

</details>

### Step 16: Flag discovery and validation
![Flag Discovery](picture19.png)

<details>
<summary>Click to expand - Flag identification and submission</summary>

Systematically identifying and validating the 5 flags hidden throughout the target website using the information gathered from previous enumeration steps.

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