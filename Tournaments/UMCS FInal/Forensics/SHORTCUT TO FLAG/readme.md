# Shortcut to Flag

> Category: Forensics 🕵️

![img](image1)

## 🔍 Overview

One of our analysts noticed suspicious activity originating from a workstation after an employee clicked what appeared to be a password file.  
Upon investigation, we found this mysterious `.LNK` file in their **Downloads** folder.

---

## ✨ Solution

### Step 1: Inspect the LNK file
We started with the `password.lnk` file. Since it’s a Windows shortcut, we analyzed it using the **lnkparse** tool to extract detailed metadata.

![img](image2)

The output revealed **command-line arguments** used by the challenge creator.  
Most importantly, it showed an **Encoding Byte process**.

---

### Step 2: Decode the payload
The `.lnk` file contained obfuscated data. To recover it, we:

1. Skipped the **first 3044 bytes** (junk data).  
2. Applied **XOR decryption with key `0x38`** to the rest of the bytes.  
3. Saved the output as an executable (`.exe`).  

![img](image3)

---

### Step 3: Analyze the executable
Next, we examined the recovered `.exe` file:

- Using `strings`, we found suspicious values inside.  
- Opening the file in **dnSpy** revealed that the program renamed itself to `umcs`.  
- The entry point was located at the `P.Main` function.  

![img](image4)

---

### Step 4: Review the C# code
The decompiled C# program showed the following:

```csharp
private static void Main(string[] a)
{
    P.F("BFE835EC4F752566B213A12E79CD76B85885D03A7AC457707ED3065A92C7229EE2574D045F1D");
}
