---
title: "Bitlocker-2 CTF Writeup"
---

## 🔑 Bitlocker-2 Challenge Writeup
In this challenge, I extracted a BitLocker key from a RAM dump using **Volatility**.

**Steps:**
1. Loaded the memory dump into Volatility.
2. Used `vol.py -f memdump.raw --profile=Win10x64 bitlocker` to extract the key.
3. Successfully retrieved the recovery key.

🔗 [Back to Home](index.md)
