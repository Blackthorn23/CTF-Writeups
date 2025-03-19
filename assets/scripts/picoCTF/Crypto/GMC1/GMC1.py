from sympy import mod_inverse

def affine_decrypt(ciphertext, a, b):
    m = 26  # Alphabet size
    a_inv = mod_inverse(a, m)  # Find modular inverse of a
    decrypted_text = ""
    
    for char in ciphertext:
        if char.isalpha():
            x = ord(char) - ord('A')  # Convert letter to number (0-25)
            decrypted_char = chr(((a_inv * (x - b)) % m) + ord('A'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += char  # Preserve non-alphabet characters
    
    return decrypted_text

def find_affine_params(plaintext, ciphertext):
    m = 26  # Alphabet size
    x1, y1 = ord(plaintext[0]) - ord('A'), ord(ciphertext[0]) - ord('A')
    x2, y2 = ord(plaintext[1]) - ord('A'), ord(ciphertext[1]) - ord('A')
    
    # Solve for 'a' and 'b':
    a = (y1 - y2) * mod_inverse(x1 - x2, m) % m
    b = (y1 - a * x1) % m
    return a, b

# Known encryptions
plaintext1, ciphertext1 = "MOZZARELLA", "PFCCXQDUUX"
plaintext2, ciphertext2 = "CHEDDAR", "NODIIXQ"

# Find affine parameters
try:
    a, b = find_affine_params(plaintext1, ciphertext1)
except:
    a, b = find_affine_params(plaintext2, ciphertext2)

print(f"Found affine parameters: a={a}, b={b}")

# Given encrypted cheese name
ciphertext = "TFLADUGTQDDKWGR"
decrypted_text = affine_decrypt(ciphertext, a, b)
print(f"Decrypted cheese: {decrypted_text}")
