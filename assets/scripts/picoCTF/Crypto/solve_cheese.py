import socket
import re
import json

# Load the precomputed rainbow table
with open("rainbow_table.json", "r") as f:
    hash_table = json.load(f)

# Server details
HOST = "verbal-sleep.picoctf.net"
PORT = 52980

def solve_cheese():
    """ Connects to the server, extracts the hash, finds the cheese from the table, and submits it. """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = s.recv(4096).decode()

        # Extract hash
        match = re.search(r"Here's my secret cheese -- .*?:\s*([a-f0-9]{64})", data)
        if not match:
            print("Could not extract hash from server response.")
            return

        target_hash = match.group(1)
        print(f"Extracted Hash: {target_hash}")

        # Find the correct cheese in the rainbow table
        if target_hash in hash_table:
            correct_cheese, correct_salt = hash_table[target_hash]
        else:
            print("Hash not found in rainbow table.")
            return

        print(f"Found Cheese: {correct_cheese} with Salt: {correct_salt}")

        # Enter guessing mode and submit the answer
        s.sendall(b"g\n")
        s.recv(1024)  # Read prompt
        s.sendall(correct_cheese.encode() + b"\n")
        s.recv(1024)  # Read response before sending salt
        s.sendall(correct_salt.encode() + b"\n")

        # Get the final response
        final_response = s.recv(4096).decode()
        print("\nServer Response:\n", final_response)

# Run the solver
solve_cheese()
