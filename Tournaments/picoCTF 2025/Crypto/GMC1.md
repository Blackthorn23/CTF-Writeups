# 🧀 Guess My Cheese (Part 1) - PicoCTF 2025

**Category:** Cryptography | **Difficulty:** Easy | **Points:** TBD

Dive into the world of classical cryptography with this Affine Cipher challenge. Learn to break linear equation-based encryption through mathematical analysis.

---

## 🎯 Challenge Overview

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 15px; margin: 20px 0;">
  <h3 style="margin-top: 0; color: white;">🔗 Connection Details</h3>
  <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; font-family: monospace;">
    <strong>Server:</strong> verbal-sleep.picoctf.net<br>
    <strong>Port:</strong> 58487<br>
    <strong>Command:</strong> <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">nc verbal-sleep.picoctf.net 58487</code>
  </div>
</div>

<div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 10px; padding: 20px; margin: 20px 0;">
  <h4 style="margin-top: 0; color: #856404;">💡 Challenge Hint</h4>
  <blockquote style="margin: 10px 0; font-style: italic; border-left: 4px solid #f39c12; padding-left: 15px;">
    "Remember that cipher we devised together, Squeexy? The one that incorporates your affinity for linear equations???"
  </blockquote>
  <p style="margin-bottom: 0; color: #856404;"><strong>Key Insight:</strong> The hint points directly to an <strong>Affine Cipher</strong> - a type of monoalphabetic substitution cipher based on linear equations!</p>
</div>

---

## 🔍 Solution Walkthrough

### Step 1: Reconnaissance 🕵️

<div style="display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin: 20px 0;">
  <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 4px solid #17a2b8;">
    <h4 style="margin-top: 0; color: #17a2b8;">🎯 Objective</h4>
    <p>Connect to the server and understand the challenge mechanics</p>
  </div>
  <div>
    <p>First, let's connect to the server using netcat to see what the challenge offers:</p>
  </div>
</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="../../assets/images/picoCTF/Crypto/GMC1/GMC1(nc).png" alt="Initial connection to the challenge server" style="border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); max-width: 100%;" />
  <p style="color: #666; font-style: italic; margin-top: 10px;">Initial connection showing the challenge interface</p>
</div>

**🎮 Challenge Interface Analysis:**
- **Option (e):** Encrypt a cheese name of our choice
- **Option (g):** Guess the original cheese from an encrypted version  
- **⚠️ Limitation:** Only **3 total attempts** (2 encryptions + 1 guess)

### Step 2: Gathering Intel 🧠

<div style="background: #e8f4fd; border: 1px solid #bee5eb; border-radius: 10px; padding: 20px; margin: 20px 0;">
  <h4 style="margin-top: 0; color: #0c5460;">🔬 Encryption Testing</h4>
  <p>Let's encrypt two different cheese names to analyze the cipher pattern:</p>
</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="../../assets/images/picoCTF/Crypto/GMC1/GMC(e).png" alt="Encryption examples showing cipher pattern" style="border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); max-width: 100%;" />
  <p style="color: #666; font-style: italic; margin-top: 10px;">Encryption results revealing the cipher structure</p>
</div>

**🔍 Pattern Analysis:**
- Each letter maps to exactly one other letter consistently
- This confirms a **monoalphabetic substitution cipher**
- The linear equation hint suggests an **Affine Cipher**

### Step 3: Mathematical Cryptanalysis 📊

<div style="background: #f8f9fa; padding: 25px; border-radius: 15px; margin: 20px 0; border-left: 5px solid #e74c3c;">
  <h4 style="margin-top: 0; color: #e74c3c;">📐 Affine Cipher Mathematics</h4>
  
  The Affine Cipher uses the following transformation:
  
  <div style="background: white; padding: 20px; border-radius: 10px; margin: 15px 0; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <strong>Encryption:</strong> <code style="background: #f1f3f4; padding: 8px 12px; border-radius: 6px; font-size: 1.1em;">E(x) = (a × x + b) mod 26</code><br><br>
    <strong>Decryption:</strong> <code style="background: #f1f3f4; padding: 8px 12px; border-radius: 6px; font-size: 1.1em;">D(x) = a⁻¹ × (x - b) mod 26</code>
  </div>
  
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
    <div style="background: #e3f2fd; padding: 15px; border-radius: 8px;">
      <strong>Variables:</strong><br>
      • <code>a</code> = multiplicative key<br>
      • <code>b</code> = additive key<br>
      • <code>x</code> = letter position (A=0, B=1, ...)
    </div>
    <div style="background: #f3e5f5; padding: 15px; border-radius: 8px;">
      <strong>Requirements:</strong><br>
      • <code>gcd(a, 26) = 1</code><br>
      • Valid values for <code>a</code>: {1,3,5,7,9,11,15,17,19,21,23,25}<br>
      • <code>b</code> can be any value 0-25
    </div>
  </div>
</div>

### Step 4: Solution Implementation 💻

<div style="background: #2d3748; color: #e2e8f0; padding: 25px; border-radius: 15px; margin: 20px 0;">
  <h4 style="margin-top: 0; color: #4299e1;">🐍 Python Solution Strategy</h4>
  
  <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
    <strong>Algorithm Steps:</strong>
    <ol style="margin: 10px 0; padding-left: 20px;">
      <li>Use our two known plaintext-ciphertext pairs</li>
      <li>Set up a system of linear equations</li>
      <li>Solve for coefficients <code>a</code> and <code>b</code></li>
      <li>Apply the decryption formula to the target ciphertext</li>
    </ol>
  </div>
  
  <p style="margin: 15px 0;">
    📜 <strong>Implementation:</strong> 
    <a href="../../assets/scripts/picoCTF/Crypto/GMC1/GMC1.py" style="color: #4299e1; text-decoration: none; font-weight: bold;">
      View the complete Python solution →
    </a>
  </p>
</div>

### Step 5: Breaking the Cipher 🔓

**🎯 Target Ciphertext:** `TFLADUGTQDDKWGR`

Using our mathematical approach:

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0;">
  <div style="background: #e8f5e8; padding: 20px; border-radius: 10px; border-left: 4px solid #28a745;">
    <h5 style="margin-top: 0; color: #155724;">✅ Known Pairs</h5>
    <p style="margin: 0; font-family: monospace;">
      CHEDDAR → [encrypted]<br>
      GOUDA → [encrypted]
    </p>
  </div>
  <div style="background: #fff3cd; padding: 20px; border-radius: 10px; border-left: 4px solid #ffc107;">
    <h5 style="margin-top: 0; color: #856404;">🔄 Processing</h5>
    <p style="margin: 0;">
      Solve linear system<br>
      Find a = ? and b = ?<br>
      Apply decryption formula
    </p>
  </div>
  <div style="background: #f8d7da; padding: 20px; border-radius: 10px; border-left: 4px solid #dc3545;">
    <h5 style="margin-top: 0; color: #721c24;">🎯 Result</h5>
    <p style="margin: 0; font-weight: bold;">
      TFLADUGTQDDKWGR<br>
      ↓ decrypts to ↓<br>
      [SOLUTION]
    </p>
  </div>
</div>

---

## 🏆 The Solution

<div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 20px; margin: 30px 0; text-align: center; box-shadow: 0 8px 25px rgba(40, 167, 69, 0.3);">
  <h3 style="margin-top: 0; color: white; font-size: 1.5em;">🎉 FLAG CAPTURED!</h3>
  <div style="background: rgba(255,255,255,0.2); padding: 20px; border-radius: 15px; margin: 20px 0; font-family: monospace; font-size: 1.2em; font-weight: bold;">
    picoCTF{ChEeSy8313f058}
  </div>
  <p style="margin-bottom: 0; font-size: 1.1em;">
    🧀 Successfully decrypted the cheese name and obtained the flag!
  </p>
</div>

---

## 📚 Key Learnings

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0;">
  
  <div style="background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #e74c3c;">
    <h4 style="margin-top: 0; color: #e74c3c;">🔐 Cryptographic Concepts</h4>
    <ul style="margin: 0; color: #666;">
      <li>Affine cipher mechanics</li>
      <li>Monoalphabetic substitution</li>
      <li>Modular arithmetic</li>
      <li>Linear equation cryptanalysis</li>
    </ul>
  </div>
  
  <div style="background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #3498db;">
    <h4 style="margin-top: 0; color: #3498db;">🧮 Mathematical Skills</h4>
    <ul style="margin: 0; color: #666;">
      <li>Solving systems of linear equations</li>
      <li>Modular inverse calculation</li>
      <li>GCD understanding</li>
      <li>Pattern recognition</li>
    </ul>
  </div>
  
  <div style="background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #28a745;">
    <h4 style="margin-top: 0; color: #28a745;">💻 Technical Skills</h4>
    <ul style="margin: 0; color: #666;">
      <li>Python cryptography implementation</li>
      <li>Algorithm optimization</li>
      <li>Debugging and testing</li>
      <li>Mathematical programming</li>
    </ul>
  </div>
  
</div>

---

## 🔗 Related Challenges

<div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
  <h4 style="margin-top: 0;">🎯 Continue Your Crypto Journey</h4>
  <p>Ready for more cryptographic challenges? Try these next:</p>
  
  <div style="display: flex; gap: 15px; margin: 15px 0;">
    <a href="GMC2.md" style="background: #17a2b8; color: white; padding: 10px 20px; border-radius: 25px; text-decoration: none; font-weight: bold;">🧀 Guess My Cheese (Part 2) →</a>
    <a href="index.md" style="background: #6c757d; color: white; padding: 10px 20px; border-radius: 25px; text-decoration: none; font-weight: bold;">📋 All Crypto Challenges</a>
  </div>
</div>

---

<div style="text-align: center; margin: 40px 0;">
  <div style="background: #e9ecef; padding: 20px; border-radius: 15px;">
    <p style="margin: 0; color: #6c757d;">
      <strong>📝 Writeup by Nawfal Syafi</strong> | 
      <a href="../../index.md" style="color: #3498db; text-decoration: none;">🏠 Back to PicoCTF</a> | 
      <a href="../../../index.md" style="color: #3498db; text-decoration: none;">🏠 Home</a>
    </p>
  </div>
</div>

