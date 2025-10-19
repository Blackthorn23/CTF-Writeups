# Flag Hunters: CTF Workshop – Forensics Track

## 📌 Event Details

**Event**: Flag Hunters: CTF Workshop  
**Organizer**: GDG on Campus - Multimedia University Selangor Malaysia  
**Role**: Speaker
**Date**: 23/8/2025
**Link**: https://gdg.community.dev/events/details/google-gdg-on-campus-multimedia-university-selangor-malaysia-presents-flag-hunters-ctf-workshop/

---

## 🎯 Workshop Overview

This workshop introduced students to the **Forensics** category in Capture The Flag (CTF) competitions.  
I guided participants through **digital evidence analysis, PCAP investigations, disk/memory dumps, and hidden file techniques**, with step-by-step walkthroughs based on real challenge examples.

### 🎓 Topics Covered

1. **Introduction to Digital Forensics in CTF**  
   - What is Digital Forensics?  
   - Why it matters in CTF challenges  

2. **Types of Forensics Challenges**  
   - Network Forensics (PCAP analysis)  
   - Disk & Memory Forensics (image & RAM dumps)  
   - File Analysis (metadata, hidden data, corruption repair)  

3. **Network Forensics**  
   - Packet analysis with Wireshark  
   - OSI & TCP/IP models in CTF context  
   - Using filters (`http`, `ftp`, `tcp`, `udp`)  
   - Following streams & exporting objects  

4. **Disk & Memory Forensics**  
   - Analyzing disk images (.dd, .img, .iso)  
   - Recovering deleted files and persistence artifacts  
   - Memory dumps (.raw, .dmp, .vmem) and volatility analysis  
   - Finding credentials, injected code, and malware in RAM  

5. **File Analysis Techniques**  
   - Identifying file type (`file`)  
   - Extracting metadata (`exiftool`)  
   - Hidden data discovery (`strings`, `binwalk`)  
   - Hex inspection (`xxd`, `hexedit`)  
   - File carving (`foremost`, `scalpel`)  
   - Integrity checks (MD5, SHA1, SHA256)  

6. **Fun Challenge**  
   - Hands-on forensic puzzle to apply learned skills  

---

### 🛠️ Tools Demonstrated

- **Wireshark** → Network packet analysis  
- **Volatility / Rekall** → Memory dump analysis  
- **Autopsy / Sleuth Kit / FTK Imager** → Disk forensics  
- **CyberChef** → Encoding/decoding & transformations  
- **Strings / Exiftool / Binwalk** → File inspection & metadata  
- **Foremost / Scalpel** → File carving & recovery  

---

### 🏆 Workshop Challenges

The session included practical forensic tasks:

1. **Network Forensics Challenge** → Recover hidden credentials in a PCAP  
2. **Disk Image Challenge** → Extract deleted files from a `.dd` image  
3. **Memory Forensics Challenge** → Investigate processes & find malware trace  
4. **File Analysis Challenge** → Detect and extract hidden data from a file  

---

### 📊 Outcomes

- **Participants**: 30+ university students  
- **Completion Rate**: ~80% solved at least 3 forensic challenges  
- **Feedback**: Students enjoyed the step-by-step walkthroughs and practical nature  
- **Follow-up**: Many participants explored Volatility and Wireshark further after the workshop  

---

### 📚 Resources Provided

- Workshop slides & forensic reference material  
- Challenge files & detailed solutions  
- Recommended forensic tools & cheat sheets  
- Beginner-friendly resources for deeper practice  

---

## 🎓 Reflection

Facilitating the **Forensics track** was a great opportunity to show students how digital investigation skills apply in CTFs.  

This track highlighted the importance of:  
- **Analytical Thinking** → approaching problems like investigators  
- **Hands-On Practice** → tools are best learned through real data  
- **System Knowledge** → understanding OS, filesystems, and memory internals  
- **Persistence** → forensic challenges often require patience & creativity  

---

## 🔗 Links

- **Event Page**: https://gdg.community.dev/events/details/google-gdg-on-campus-multimedia-university-selangor-malaysia-presents-flag-hunters-ctf-workshop/  
- **Workshop Slides**: [Presentaion_Slides_Forensics.pdf](/Presentaion_Slides_Forensics.pdf)  
- **Forensics Tools Reference**: [CyberChef](https://gchq.github.io/CyberChef/), [Volatility](https://github.com/volatilityfoundation/volatility), [Wireshark](https://www.wireshark.org/)  

---
