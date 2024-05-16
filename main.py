import random
import hashlib

# Step 1: Select a random private key 'a'
def generate_private_key(p):
    # Generate a random integer 'a' such that 1 < a < p-1
    # Implement your own random integer generator or use a library like random
    return random.randint(2, p-2)

# Step 2: Calculate public key 'ga (mod p)'
def calculate_public_key(a, g, p):
    return pow(g, a, p)

# Step 3: Calculate the hashed password
def calculate_hashed_password(password, salt):
    x = hashlib.sha256(salt.encode() + password.encode()).digest()
    return int.from_bytes(x, 'big') ** 1000

# Step 4: Calculate server's DH public key 'g^b'
def calculate_server_public_key(B, x, g, k, p):
    return (B - k * pow(g, x, p)) % p

# Step 5: Calculate values 'u' and 'k'
def calculate_u_and_k(g, ga, gb, p):
    u = hashlib.sha256(int_to_bytes(ga) + int_to_bytes(gb)).digest()
    k = hashlib.sha256(int_to_bytes(p) + int_to_bytes(g)).digest()
    return int.from_bytes(u, 'big'), int.from_bytes(k, 'big')

# Step 6: Calculate the shared key
def calculate_shared_key(private_key, public_key, u, x, p):
    return pow(public_key, private_key, p) * u * x % p

# Step 7: Calculate M1
def calculate_M1(password, netId, salt, g, public_key_a, public_key_b, shared_key):
    H_p = hashlib.sha256(password.encode()).digest()
    H_g = hashlib.sha256(str(g).encode()).digest()
    M1_input = bytearray(H_p) + bytearray(H_g) + hashlib.sha256(netId.encode()).digest() + salt.encode() + int_to_bytes(public_key_a) + int_to_bytes(public_key_b) + int_to_bytes(shared_key)
    M1_input = bytes([a ^ b for a, b in zip(M1_input[:len(H_p)], H_g)]) + M1_input[len(H_p):]
    return hashlib.sha256(M1_input).digest()

# Step 8: Calculate M2
def calculate_M2(public_key_a, M1, shared_key):
    M2_input = int_to_bytes(public_key_a) + M1 + int_to_bytes(shared_key)
    return hashlib.sha256(M2_input).digest()

# Helper function to convert integer to bytes
def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

# Example usage
def main():
    # Given Diffie-Hellman parameters
    p = 23  # Prime modulus
    g = 5   # Generator

    # Server-provided values
    B = 6   # Server's DH public key
    salt = "somesalt"  # Salt
    password = "password"  # Password

    # Step 1: Select a random private key 'a'
    private_key = generate_private_key(p)

    # Step 2: Calculate public key 'ga (mod p)'
    public_key_a = calculate_public_key(private_key, g, p)

    # Step 3: Calculate the hashed password
    x = calculate_hashed_password(password, salt)

    # Step 4: Calculate server's DH public key 'g^b'
    k = hashlib.sha256(int_to_bytes(p) + int_to_bytes(g)).digest()
    public_key_b = calculate_server_public_key(B, x, g, int.from_bytes(k, 'big'), p)

    # Step 5: Calculate values 'u' and 'k'
    u, k = calculate_u_and_k(g, public_key_a, public_key_b, p)

    # Step 6: Calculate the shared key
    shared_key = calculate_shared_key(private_key, public_key_b, u, x, p)

    # Step 7: Calculate M1
    M1 = calculate_M1(password, "netId", salt, g, public_key_a, public_key_b, shared_key)

    # Step 8: Calculate M2
    M2 = calculate_M2(public_key_a, M1, shared_key)

    print("Shared Key:", shared_key)
    print("M1:", M1)
    print("M2:", M2)

if __name__ == "__main__":
    main()
