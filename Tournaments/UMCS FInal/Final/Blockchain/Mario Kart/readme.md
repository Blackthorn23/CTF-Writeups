# Mario Kart

> Category: Blockchain ⛓️

![img](question.png)

## 🔍 Overview

Vrooom vroom Mario!!!  

The objective is to solve the challenge by completing a smart contract-based race hosted in a contract called **MarioKart**.  
We don’t have direct access to the full source code, but we’re given the ABI fragments for both the Setup and MarioKart contracts.  
The Setup contract exposes a function called `isSolved()` that returns true once the challenge is complete.  

Our job is to reverse-engineer the race logic and interact with the contract correctly to solve the challenge and obtain the flag.

---

## ✨ Walkthrough

For this challenge we are given 2 SOL files. Analyzing them we found that:  

1. **Step 1: Find the MarioKart Contract Address**  
   The Setup contract contains a function `getMainContract()` that returns the address of the main challenge contract.  
   We can call it directly using Web3.

![img](picture1.png)

2. **Step 2: Join the Race**  
   The first step in the contract logic is to join the race using the `joinRace(string)` payable function.  
   It requires exactly 1 ETH with a name (e.g., "Haxor").  

![img](picture2.png)

3. **Step 3: Start the Race**  
   Once we’ve joined, we need to start the race by calling the `startRace()` function.  

![img](picture3.png)

4. **Step 4: Accelerate Until Finish**  
   To progress in the race, we repeatedly call `accelerate()` until the `raceFinished()` flag returns true.  

![img](picture4.png)

5. **Step 5: Check if the Challenge is Solved**  
   Finally, once the race is finished, we query the Setup contract to check if we successfully completed the challenge.  

![img](picture5.png)

---

## 🚩 Flag
```
umcs{0c3cb3bc7201f52854752b5b490164be}
```

---

## 📝 Notes
- We interacted with the contract using Web3.  
- Required steps were: Join the race → Start race → Accelerate until finished → Check `isSolved()`.  
- The challenge simulated a blockchain race puzzle.  
