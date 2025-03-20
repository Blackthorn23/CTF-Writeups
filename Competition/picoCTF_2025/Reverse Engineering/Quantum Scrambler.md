### PicoCTF 2024 - Quantum Entanglement Cipher Writeup

#### Challenge Description
```
We invented a new cypher that uses "quantum entanglement" to encode the flag.
Do you have what it takes to decode it?

Connect to the program with netcat:
$ nc verbal-sleep.picoctf.net 60759
```

#### Step 1: Retrieving the Scrambled Output
We use `nc` to connect to the challenge server and save the output to a file:

```bash
nc verbal-sleep.picoctf.net 60759 > flag.txt
```

#### Step 2: Understanding the Scrambling Mechanism
The challenge provided a Python script (`quantum_scrambler.py`) that:
- Reads the flag from `flag.txt`
- Converts each character to its hexadecimal representation
- Applies a scrambling function that nests the hex values in a complex list structure

#### Step 3: Running the Decoder
We have provided a decoder script to extract the flag. You can download it here:

[scramble.py](assest/script/scramble.py)

Run the script using:

```bash
python3 assest/script/decode.py
cat scrambled_flag.txt
```

#### Step 4: Capturing the Flag
After running the script, we obtain the flag:
```
picoCTF{python_is_weirde2a45ca5}
```

### Conclusion
This challenge involved understanding how a function manipulates data structures and reversing the transformation. By flattening the nested structure and extracting the hex values, we successfully recovered the original flag.
