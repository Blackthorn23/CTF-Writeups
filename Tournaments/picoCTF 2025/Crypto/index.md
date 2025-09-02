---
layout: default
title: "PicoCTF 2025 - Cryptography Challenges"
description: "Cryptography challenge writeups from PicoCTF 2025"
---

<div align="center">
  <h1>🔐 PicoCTF 2025 - Cryptography</h1>
  <p style="font-size: 1.1em; color: #666; margin-bottom: 30px;">
    Decode secrets, break ciphers, and master the art of cryptanalysis
  </p>
  
  <div style="display: flex; justify-content: center; gap: 15px; margin-bottom: 30px;">
    <img src="https://img.shields.io/badge/Category-Cryptography-red?style=for-the-badge" alt="Cryptography" />
    <img src="https://img.shields.io/badge/Challenges-2-blue?style=for-the-badge" alt="Challenges" />
    <img src="https://img.shields.io/badge/Difficulty-Beginner-green?style=for-the-badge" alt="Difficulty" />
  </div>
</div>

---

## 🧀 Challenge List

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin: 30px 0;">

  <div style="border: 2px solid #ff6b6b; border-radius: 15px; padding: 25px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); color: white; box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);">
    <h3 style="margin-top: 0; color: white; display: flex; align-items: center;">
      🧀 Guess My Cheese (Part 1)
      <span style="background: rgba(255,255,255,0.3); font-size: 0.7em; padding: 3px 8px; border-radius: 10px; margin-left: 10px;">Easy</span>
    </h3>
    <p style="margin: 15px 0; line-height: 1.5;">
      <strong>Challenge Type:</strong> Affine Cipher<br>
      <strong>Key Concepts:</strong> Linear equations, Modular arithmetic<br>
      <strong>Tools Used:</strong> Python, Mathematical analysis
    </p>
    <div style="background: rgba(255,255,255,0.2); border-radius: 8px; padding: 12px; margin: 15px 0;">
      <strong>💡 What You'll Learn:</strong>
      <ul style="margin: 5px 0; padding-left: 20px;">
        <li>Affine cipher mechanics</li>
        <li>Solving linear equations in cryptography</li>
        <li>Pattern recognition in ciphertexts</li>
      </ul>
    </div>
    <a href="GMC1.md" style="background: rgba(255,255,255,0.2); color: white; padding: 12px 20px; border-radius: 25px; text-decoration: none; font-weight: bold; display: inline-block; margin-top: 10px;">📖 Read Writeup →</a>
  </div>

  <div style="border: 2px solid #4ecdc4; border-radius: 15px; padding: 25px; background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%); color: white; box-shadow: 0 4px 15px rgba(78, 205, 196, 0.3);">
    <h3 style="margin-top: 0; color: white; display: flex; align-items: center;">
      🧀 Guess My Cheese (Part 2)
      <span style="background: rgba(255,255,255,0.3); font-size: 0.7em; padding: 3px 8px; border-radius: 10px; margin-left: 10px;">Easy</span>
    </h3>
    <p style="margin: 15px 0; line-height: 1.5;">
      <strong>Challenge Type:</strong> Advanced Cipher Analysis<br>
      <strong>Key Concepts:</strong> Pattern matching, Brute force<br>
      <strong>Tools Used:</strong> Python, Rainbow tables
    </p>
    <div style="background: rgba(255,255,255,0.2); border-radius: 8px; padding: 12px; margin: 15px 0;">
      <strong>💡 What You'll Learn:</strong>
      <ul style="margin: 5px 0; padding-left: 20px;">
        <li>Rainbow table attacks</li>
        <li>Optimized search algorithms</li>
        <li>Pattern-based cryptanalysis</li>
      </ul>
    </div>
    <a href="GMC2.md" style="background: rgba(255,255,255,0.2); color: white; padding: 12px 20px; border-radius: 25px; text-decoration: none; font-weight: bold; display: inline-block; margin-top: 10px;">📖 Read Writeup →</a>
  </div>

</div>

---

## 🛠️ Cryptography Toolkit

<div style="background: #f8f9fa; padding: 25px; border-radius: 15px; margin: 30px 0; border-left: 5px solid #ff6b6b;">
  <h3 style="margin-top: 0; color: #ff6b6b;">Essential Tools for Crypto Challenges</h3>
  
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
    
    <div style="background: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
      <h4 style="margin-top: 0; color: #333;">🐍 Python Libraries</h4>
      <ul style="margin: 0; color: #666;">
        <li>pycryptodome</li>
        <li>sympy (for math)</li>
        <li>itertools</li>
        <li>string manipulation</li>
      </ul>
    </div>
    
    <div style="background: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
      <h4 style="margin-top: 0; color: #333;">🔧 Online Tools</h4>
      <ul style="margin: 0; color: #666;">
        <li>CyberChef</li>
        <li>dCode.fr</li>
        <li>Cryptii</li>
        <li>Online calculators</li>
      </ul>
    </div>
    
    <div style="background: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
      <h4 style="margin-top: 0; color: #333;">📊 Analysis Methods</h4>
      <ul style="margin: 0; color: #666;">
        <li>Frequency analysis</li>
        <li>Pattern recognition</li>
        <li>Mathematical modeling</li>
        <li>Brute force</li>
      </ul>
    </div>
    
  </div>
</div>

---

## 🎓 Learning Path

<div style="display: flex; flex-direction: column; gap: 15px; margin: 30px 0;">
  
  <div style="display: flex; align-items: center; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid #4caf50;">
    <div style="background: #4caf50; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 20px; font-weight: bold;">1</div>
    <div>
      <strong>Start with Classical Ciphers</strong>
      <p style="margin: 5px 0; color: #666;">Caesar, Vigenère, Affine ciphers - understand the fundamentals</p>
    </div>
  </div>
  
  <div style="display: flex; align-items: center; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid #2196f3;">
    <div style="background: #2196f3; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 20px; font-weight: bold;">2</div>
    <div>
      <strong>Learn Frequency Analysis</strong>
      <p style="margin: 5px 0; color: #666;">Statistical analysis of text patterns and character distributions</p>
    </div>
  </div>
  
  <div style="display: flex; align-items: center; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid #ff9800;">
    <div style="background: #ff9800; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 20px; font-weight: bold;">3</div>
    <div>
      <strong>Practice Mathematical Cryptography</strong>
      <p style="margin: 5px 0; color: #666;">Modular arithmetic, prime numbers, and algebraic structures</p>
    </div>
  </div>
  
</div>

---

<div style="text-align: center; margin: 40px 0;">
  <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 15px; margin: 20px 0;">
    <h3 style="margin-top: 0;">🎯 Ready to start your crypto journey?</h3>
    <p style="margin: 10px 0;">Begin with the Guess My Cheese challenges to learn the fundamentals!</p>
    <a href="GMC1.md" style="background: rgba(255,255,255,0.2); color: white; padding: 12px 25px; border-radius: 25px; text-decoration: none; font-weight: bold; margin: 0 10px;">Start with GMC1 →</a>
  </div>
</div>

---

<div style="text-align: center; margin-top: 40px;">
  <a href="../index.md" style="background: #6c757d; color: white; padding: 12px 25px; border-radius: 25px; text-decoration: none; font-weight: bold; margin: 0 10px;">← Back to PicoCTF</a>
  <a href="../../index.md" style="background: #667eea; color: white; padding: 12px 25px; border-radius: 25px; text-decoration: none; font-weight: bold; margin: 0 10px;">🏠 Home</a>
</div>

