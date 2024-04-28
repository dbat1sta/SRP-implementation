import random
import hashlib

def generate_private_key(p):
    return random.randint(2, p-2)

def calculate_public_key(a, g, p):
    return pow(g, a, p)

def calculate_shared_key(private_key, public_key, p):
    return pow(public_key, private_key, p)

def sha256_hash(value):
    if isinstance(value, int):
        value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    elif isinstance(value, str):
        value = value.encode('ascii')
    return hashlib.sha256(value).digest()

def main():
    p = 23  # Prime modulus
    g = 5   # Generator

    private_key = generate_private_key(p)

    public_key = calculate_public_key(private_key, g, p)

    shared_key = calculate_shared_key(private_key, public_key, p)

    hashed_shared_key = sha256_hash(shared_key)

    print("Shared Key (before hashing):", shared_key)
    print("Shared Key (after hashing):", hashed_shared_key)

if __name__ == "__main__":
    main()
