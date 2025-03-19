## 🧀 Guess My Cheese (Part 1)
### The Question Asked
<img src="../../assets/images/picoCTF/GMS1(question).png" alt="Guess My Cheese Question" width="200" />

### The Given Hint:  
> Remember that cipher we devised together, Squeexy?  
> The one that incorporates your affinity for linear equations???

---

### Steps:
#### 1️⃣ Connecting to the Challenge
First, let's connect to the server using `nc` (netcat) to see what the challenge is about.  
<img src="../../assets/images/picoCTF/GMC1(nc).png" alt="Guess My Cheese Question" width="200" />

#### 2️⃣ Understanding the Challenge
We are given **two options**:  
- **(e)** Encrypt a cheese name  
- **(g)** Guess the original cheese from an encrypted version  

However, we only have **three attempts** in total—**two encryption attempts and one guess**.  
<img src="../../assets/images/picoCTF/GMC(e).png" alt="Guess My Cheese Question" width="200" />

#### 3️⃣ Identifying the Cipher Type  
From the encrypted outputs of two different cheese names, we can determine that this is a **monoalphabetic substitution cipher**. But which specific type?  

#### 4️⃣ Analyzing the Hint  
The hint references **"affinity for linear equations"**, which strongly suggests an **Affine Cipher**.  
To confirm this, we checked with ChatGPT about possible ciphers that match this pattern:  
<img src="../../assets/images/picoCTF/GMC(chat).png" alt="Guess My Cheese Question" width="200" />

#### 5️⃣ Solving the Affine Cipher  
The **Affine Cipher** follows the encryption formula:

\[
E(x) = (a \cdot x + b) \mod 26
\]

To decrypt, we use:

\[
D(x) = a^{-1} \cdot (x - b) \mod 26
\]

Using the encryptions of two known cheese names, we can solve for `a` and `b`, then decrypt the given cheese name:  
> **"TFLADUGTQDDKWGR"**  

I wrote a Python script to automate this decryption:  
📜 **[GMC1.py](../../assets/scripts/picoCTF/GMC1.py)**  

🔗 [Back to Home](../index.md)

