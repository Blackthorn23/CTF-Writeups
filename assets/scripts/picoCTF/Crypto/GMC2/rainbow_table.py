import hashlib
import itertools

# Load cheese names
with open("cheese_list.txt", "r") as file:
    cheese_names = [line.strip() for line in file if line.strip()]

# Target hash
target_hash = "305e07703291e90e2f54d31dfc5a5adf6e08b7ebb6c4ad83ee2d0851805411d4"

# Generate 2-character hex salts (00-FF)
hex_salts = [f"{i:02x}" for i in range(256)]

# Different transformations of cheese names
transformations = [
    lambda c: c,               # Original
    lambda c: c.lower(),        # Lowercase
    lambda c: c.replace(" ", ""),  # Remove spaces
    lambda c: c.replace(" ", "_"), # Replace spaces with underscores
]

# Different salt placements
salt_placements = [
    lambda c, s: s + c,  # Salt at beginning
    lambda c, s: c + s,  # Salt at end
    lambda c, s: c[:len(c)//2] + s + c[len(c)//2:],  # Salt in the middle
]

# Different encodings
encodings = ["utf-8", "utf-16", "utf-32"]

# Try all variations
for cheese in cheese_names:
    for transform in transformations:
        transformed_cheese = transform(cheese)

        for salt in hex_salts:
            for place_salt in salt_placements:
                salted_cheese = place_salt(transformed_cheese, salt)

                for encoding in encodings:
                    try:
                        hashed_value = hashlib.sha256(salted_cheese.encode(encoding)).hexdigest()
                        if hashed_value == target_hash:
                            print(f"Found! Cheese: {cheese}, Salt: {salt}, Encoding: {encoding}")
                            exit()
                    except Exception:
                        continue  # Ignore encoding errors

print("No match found.")
